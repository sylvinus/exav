import type { BufferGeometry, Mesh, Object3D } from "three";

import { writable } from "../core/store.js";
import type { GroundController, LayersController, Renderer, Selection } from "../core/types.js";
import { createModelEngine, DEFAULT_MAX_TRIANGLES, DEFAULT_TIMEOUT_MS, modelWarnings, type ParsedModel } from "../model/engine.js";
import { elementBoxes, framingBox } from "../model/framing.js";
import type { IfcOptions } from "./index.js";

const GROUNDS = { light: "#ffffff", dark: "#212830" } as const;

/** What has to follow the ground or disappear into it: the outlines, and the grid. */
const INK = {
  light: { edges: "#334155", grid: "#cbd5e1" },
  dark: { edges: "#cbd5e1", grid: "#475569" },
} as const;

/** Hidden until asked for: rooms are boxes around everything else. */
const HIDDEN_AT_FIRST = new Set(["IFCSPACE"]);

/**
 * A colour per category, derived from its name so the same class is the same
 * colour in every model (IFC has some nine hundred). Also the fill of
 * elements the file gives no colour.
 */
export function categoryColor(name: string): string {
  return `hsl(${categoryHue(name)} 42% 58%)`;
}

function categoryHue(name: string): number {
  let hash = 0;
  for (const c of name) hash = (hash * 31 + c.charCodeAt(0)) | 0;
  return Math.abs(hash) % 360;
}

export const renderer: Renderer<IfcOptions> = {
  async mount(host, ctx) {
    ctx.status({ phase: "loading" });
    const colors = { ...GROUNDS, ...ctx.options.colors };
    const engine = createModelEngine();
    let destroyed = false;
    const disposers: (() => void)[] = [() => engine.destroy()];
    const destroy = () => {
      if (destroyed) return;
      destroyed = true;
      for (const d of disposers.splice(0).reverse()) d();
    };
    // A session closed while the model is still being read: the worker is
    // stopped now, not when it would have finished.
    ctx.signal.addEventListener("abort", destroy, { once: true });

    try {
      const [three, { OrbitControls }, source] = await Promise.all([
        import("three"),
        import("three/examples/jsm/controls/OrbitControls.js"),
        ctx.source.bytes(),
      ]);
      if (destroyed || ctx.signal.aborted) throw new DOMException("aborted", "AbortError");
      const bytes = source.slice();
      const model: ParsedModel = await engine.call(
        { kind: "ifc", bytes: bytes.buffer as ArrayBuffer, maxTriangles: ctx.options.maxTriangles ?? DEFAULT_MAX_TRIANGLES },
        [bytes.buffer as ArrayBuffer],
        ctx.options.timeoutMs ?? DEFAULT_TIMEOUT_MS,
      );
      // The engine's work is done: its memory goes back now.
      engine.destroy();
      if (destroyed || ctx.signal.aborted) throw new DOMException("aborted", "AbortError");
      const { meta } = model;

      const root = document.createElement("div");
      root.className = "exv-ifc";
      host.append(root);
      disposers.push(() => root.remove());

      const gl = new three.WebGLRenderer({ antialias: true });
      disposers.push(() => {
        gl.dispose();
        // Give the context back now: a browser holds about sixteen.
        gl.forceContextLoss();
        gl.domElement.remove();
      });
      gl.setPixelRatio(Math.min(window.devicePixelRatio || 1, 2));
      gl.domElement.className = "exv-model-canvas";
      root.append(gl.domElement);

      const scene = new three.Scene();
      // IFC is Z-up, three.js Y-up.
      const world = new three.Group();
      world.rotation.x = -Math.PI / 2;
      scene.add(world);
      const geometries: BufferGeometry[] = [];
      const materials: { dispose(): void }[] = [];
      disposers.push(() => {
        for (const g of geometries) g.dispose();
        for (const m of materials) m.dispose();
      });

      // Lamps that keep the file's colours recognisable: a sky over a grey
      // ground, a key light from the front right, a weaker one behind, so
      // that each side of a box has its own shade. Intensities in three.js's
      // units (pi is the albedo itself).
      scene.add(new three.HemisphereLight(0xffffff, 0x8a8f99, 1.9));
      const key = new three.DirectionalLight(0xffffff, 1.3);
      key.position.set(0.6, 1, 0.8);
      scene.add(key);
      const fill = new three.DirectionalLight(0xffffff, 0.45);
      fill.position.set(-0.8, 0.4, -0.6);
      scene.add(fill);

      let ground: "light" | "dark" = ctx.options.ground ?? "light";
      const edgeMaterial = new three.LineBasicMaterial({ color: INK[ground].edges, transparent: true, opacity: 0.55 });
      materials.push(edgeMaterial);

      // One mesh (and one outline) per batch, grouped by class to hide.
      const byClass = new Map<string, Object3D[]>();
      const meshes: Mesh[] = [];
      /** Per batch, its triangle -> element. */
      const owner: Int32Array[] = meta.batches.map((b) => new Int32Array(b.indices / 3).fill(-1));
      meta.elements.forEach((e, i) => {
        for (const [b, first, count] of e.ranges) owner[b]?.fill(i, first / 3, (first + count) / 3);
      });
      meta.batches.forEach((b, i) => {
        const geometry = new three.BufferGeometry();
        geometry.setAttribute("position", new three.BufferAttribute(model.positions.subarray(b.vertex * 3, (b.vertex + b.vertices) * 3), 3));
        geometry.setAttribute("normal", new three.BufferAttribute(model.normals.subarray(b.vertex * 3, (b.vertex + b.vertices) * 3), 3));
        geometry.setIndex(new three.BufferAttribute(model.indices.subarray(b.index, b.index + b.indices), 1));
        geometries.push(geometry);
        const alpha = b.color?.[3] ?? 1;
        // The swatch's colour where the file gives none (three.js does not
        // read CSS's space-separated hsl()).
        const color = b.color
          ? new three.Color().setRGB(b.color[0], b.color[1], b.color[2], three.SRGBColorSpace)
          : new three.Color().setHSL(categoryHue(b.class) / 360, 0.42, 0.58, three.SRGBColorSpace);
        const material = new three.MeshLambertMaterial({
          color,
          // Files do not agree on which way a face points.
          side: three.DoubleSide,
          transparent: alpha < 1,
          opacity: alpha,
          depthWrite: alpha >= 1,
          // The outline is drawn over the faces it borders.
          polygonOffset: true,
          polygonOffsetFactor: 1,
          polygonOffsetUnits: 1,
        });
        materials.push(material);
        const mesh = new three.Mesh(geometry, material);
        mesh.userData.batch = i;
        // Glass after what is behind it.
        if (alpha < 1) mesh.renderOrder = 1;
        world.add(mesh);
        meshes.push(mesh);
        const objects = [mesh as Object3D];
        if (b.edges > 0) {
          const eg = new three.BufferGeometry();
          eg.setAttribute("position", new three.BufferAttribute(model.edges.subarray(b.edge * 3, (b.edge + b.edges) * 3), 3));
          geometries.push(eg);
          const lines = new three.LineSegments(eg, edgeMaterial);
          world.add(lines);
          objects.push(lines);
        }
        const list = byClass.get(b.class) ?? [];
        list.push(...objects);
        byClass.set(b.class, list);
      });

      const names = [...byClass.keys()].sort((a, b) => a.localeCompare(b));
      const visible = new Map(names.map((n) => [n, !HIDDEN_AT_FIRST.has(n)]));
      const applyVisibility = () => {
        for (const [n, objects] of byClass) for (const o of objects) o.visible = visible.get(n) ?? true;
      };
      applyVisibility();

      // What the view is framed on, in model metres relative to its origin:
      // the elements, less any left far from the rest.
      const b = framingBox(elementBoxes(meta, model.positions, model.indices)) ?? meta.bounds ?? [0, 0, 0, 1, 1, 1];
      const box = new three.Box3(new three.Vector3(b[0], b[2], -b[4]), new three.Vector3(b[3], b[5], -b[1]));
      const sphere = box.getBoundingSphere(new three.Sphere());
      const radius = Math.max(sphere.radius, 0.5);

      // A floor grid under the model, a metre per cell up to a hundred cells.
      const span = Math.max(box.max.x - box.min.x, box.max.z - box.min.z, 1) * 1.5;
      const cells = Math.min(Math.max(Math.round(span), 10), 100);
      let grid = new three.GridHelper(span, cells, INK[ground].grid, INK[ground].grid);
      const placeGrid = () => {
        grid.position.set(sphere.center.x, box.min.y - radius * 0.001, sphere.center.z);
        scene.add(grid);
      };
      placeGrid();
      disposers.push(() => {
        grid.geometry.dispose();
        (grid.material as { dispose(): void }).dispose();
      });

      const camera = new three.PerspectiveCamera(45, 1, radius / 1000, radius * 100);
      // Framed from the front, above and to the right.
      const direction = new three.Vector3(1, 0.7, 1).normalize();
      const distance = radius / Math.sin(((camera.fov / 2) * Math.PI) / 180);
      camera.position.copy(sphere.center).addScaledVector(direction, distance);
      const controls = new OrbitControls(camera, gl.domElement);
      disposers.push(() => controls.dispose());
      controls.target.copy(sphere.center);
      // Towards what is under the pointer, not the middle of the model.
      controls.zoomToCursor = true;
      controls.enableDamping = true;
      controls.update();

      let dirty = true;
      controls.addEventListener("change", () => (dirty = true));
      const paint = () => {
        scene.background = new three.Color(colors[ground]);
        edgeMaterial.color.set(INK[ground].edges);
        scene.remove(grid);
        grid.geometry.dispose();
        (grid.material as { dispose(): void }).dispose();
        grid = new three.GridHelper(span, cells, INK[ground].grid, INK[ground].grid);
        placeGrid();
        dirty = true;
      };
      paint();

      const resize = () => {
        const { clientWidth, clientHeight } = root;
        if (!clientWidth || !clientHeight) return;
        gl.setSize(clientWidth, clientHeight, false);
        camera.aspect = clientWidth / clientHeight;
        camera.updateProjectionMatrix();
        dirty = true;
      };
      resize();
      const observer = new ResizeObserver(resize);
      observer.observe(root);
      disposers.push(() => observer.disconnect());

      let frame = 0;
      const tick = () => {
        frame = requestAnimationFrame(tick);
        controls.update();
        if (!dirty) return;
        dirty = false;
        gl.render(scene, camera);
      };
      tick();
      disposers.push(() => cancelAnimationFrame(frame));

      // ── selection ──
      const selection = writable<Selection | null>(null);
      const highlightMaterial = new three.MeshBasicMaterial({
        color: ctx.options.highlight ?? "#0284c7",
        side: three.DoubleSide,
        polygonOffset: true,
        polygonOffsetFactor: -1,
        polygonOffsetUnits: -1,
      });
      materials.push(highlightMaterial);
      let highlight: Mesh | null = null;
      const clearHighlight = () => {
        if (!highlight) return;
        world.remove(highlight);
        highlight.geometry.dispose();
        highlight = null;
      };
      disposers.push(clearHighlight);
      const select = (index: number | null) => {
        clearHighlight();
        if (index === null) {
          selection.set(null);
          dirty = true;
          return;
        }
        const e = meta.elements[index]!;
        let n = 0;
        for (const [, , count] of e.ranges) n += count;
        const positions = new Float32Array(n * 3);
        let at = 0;
        for (const [bi, first, count] of e.ranges) {
          const batch = meta.batches[bi]!;
          for (let k = first; k < first + count; k++) {
            const v = (batch.vertex + model.indices[batch.index + k]!) * 3;
            positions.set(model.positions.subarray(v, v + 3), at);
            at += 3;
          }
        }
        const g = new three.BufferGeometry();
        g.setAttribute("position", new three.BufferAttribute(positions, 3));
        highlight = new three.Mesh(g, highlightMaterial);
        world.add(highlight);
        const storey = e.node !== null ? meta.nodes[e.node]?.name : undefined;
        selection.set({ name: e.name, category: e.class, ...(storey ? { storey } : {}) });
        dirty = true;
      };
      const raycaster = new three.Raycaster();
      const pointer = new three.Vector2();
      let down: { x: number; y: number } | null = null;
      const onDown = (ev: PointerEvent) => (down = { x: ev.clientX, y: ev.clientY });
      const onUp = (ev: PointerEvent) => {
        // A drag turns the view; a tap picks.
        if (!down || Math.hypot(ev.clientX - down.x, ev.clientY - down.y) > 4) return;
        down = null;
        const r = gl.domElement.getBoundingClientRect();
        pointer.set(((ev.clientX - r.left) / r.width) * 2 - 1, -((ev.clientY - r.top) / r.height) * 2 + 1);
        raycaster.setFromCamera(pointer, camera);
        const hit = raycaster.intersectObjects(
          meshes.filter((m) => m.visible),
          false,
        )[0];
        const element = hit?.faceIndex != null ? owner[hit.object.userData.batch as number]?.[hit.faceIndex] : undefined;
        select(element !== undefined && element >= 0 ? element : null);
      };
      gl.domElement.addEventListener("pointerdown", onDown);
      gl.domElement.addEventListener("pointerup", onUp);

      const layersStore = writable({
        kind: "categories" as const,
        items: names.map((n) => ({ id: n, name: n, color: categoryColor(n), visible: visible.get(n) ?? true })),
      });
      const publish = () => layersStore.set({ kind: "categories", items: names.map((n) => ({ id: n, name: n, color: categoryColor(n), visible: visible.get(n) ?? true })) });
      const setVisible = (ids: readonly string[], v: boolean) => {
        for (const id of ids) if (visible.has(id)) visible.set(id, v);
        applyVisibility();
        publish();
        dirty = true;
      };
      const layers: LayersController = {
        ...layersStore,
        setVisible: (id, v) => setVisible([id], v),
        setAll: (v) => setVisible(names, v),
      };
      const groundStore = writable(ground);
      const groundController: GroundController = {
        ...groundStore,
        colors,
        set(next) {
          ground = next;
          groundStore.set(next);
          paint();
        },
      };
      const warnings = writable(modelWarnings(meta, "ifc"));
      ctx.status(meta.elements.length > 0 ? { phase: "ready" } : { phase: "empty" });
      return {
        controllers: { layers, ground: groundController, selection, warnings },
        resize,
        destroy,
      };
    } catch (error) {
      // The worker and the context go now.
      destroy();
      throw error;
    }
  },
};
