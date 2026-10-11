import { writable } from "../core/store.js";
import type { Renderer } from "../core/types.js";
import { createModelEngine, DEFAULT_MAX_TRIANGLES, DEFAULT_TIMEOUT_MS, modelWarnings } from "./engine.js";
import type { ModelOptions } from "./index.js";

/**
 * A mid grey rather than white: the ground behind is pale, and a white part
 * on it is a silhouette with no faces.
 */
const SURFACE = 0x8c97a8;

export const renderer: Renderer<ModelOptions> = {
  async mount(host, ctx) {
    ctx.status({ phase: "loading" });
    const engine = createModelEngine();
    const disposers: (() => void)[] = [() => engine.destroy()];
    let disposed = false;
    const dispose = () => {
      disposed = true;
      for (const d of disposers.splice(0).reverse()) d();
    };
    // Closing the file while it is read stops the worker now.
    ctx.signal.addEventListener("abort", dispose, { once: true });

    try {
      const [three, { OrbitControls }, { RoomEnvironment }, source] = await Promise.all([
        import("three"),
        import("three/examples/jsm/controls/OrbitControls.js"),
        import("three/examples/jsm/environments/RoomEnvironment.js"),
        ctx.source.bytes(),
      ]);
      if (disposed || ctx.signal.aborted) throw new DOMException("aborted", "AbortError");
      const bytes = source.slice();
      const model = await engine.call(
        { kind: "stl", bytes: bytes.buffer as ArrayBuffer, maxTriangles: ctx.options.maxTriangles ?? DEFAULT_MAX_TRIANGLES },
        [bytes.buffer as ArrayBuffer],
        ctx.options.timeoutMs ?? DEFAULT_TIMEOUT_MS,
      );
      engine.destroy();
      if (disposed || ctx.signal.aborted) throw new DOMException("aborted", "AbortError");

      const root = document.createElement("div");
      root.className = "exv-model";
      host.append(root);
      disposers.push(() => root.remove());

      // The engine's facet normals, from the corners: some exporters write
      // zeros in the file, which would light a mesh black.
      const geometry = new three.BufferGeometry();
      geometry.setAttribute("position", new three.BufferAttribute(model.positions, 3));
      geometry.setAttribute("normal", new three.BufferAttribute(model.normals, 3));
      geometry.setIndex(new three.BufferAttribute(model.indices, 1));
      // The VisCAM/SolidView or Magics facet colours, as sRGB bytes.
      const coloured = (model.meta.batches[0]?.color0 ?? -1) >= 0;
      if (coloured) {
        const rgb = new Float32Array(model.colors.length);
        const c = new three.Color();
        for (let i = 0; i < rgb.length; i += 3) {
          c.setRGB(model.colors[i]! / 255, model.colors[i + 1]! / 255, model.colors[i + 2]! / 255, three.SRGBColorSpace);
          rgb[i] = c.r;
          rgb[i + 1] = c.g;
          rgb[i + 2] = c.b;
        }
        geometry.setAttribute("color", new three.BufferAttribute(rgb, 3));
      }
      disposers.push(() => geometry.dispose());
      // Every CAD application and printer means Z up; three.js means Y.
      if (ctx.options.zUp ?? true) geometry.rotateX(-Math.PI / 2);
      geometry.computeBoundingBox();
      const box = geometry.boundingBox ?? new three.Box3();
      const size = box.getSize(new three.Vector3());
      const centre = box.getCenter(new three.Vector3());
      const span = Math.max(size.x, size.y, size.z) || 1;
      const triangles = model.indices.length / 3;

      const scene = new three.Scene();
      const material = new three.MeshStandardMaterial({
        color: coloured ? 0xffffff : (ctx.options.surface ?? SURFACE),
        vertexColors: coloured,
        metalness: 0.15,
        roughness: 0.55,
        // A scan is often a surface, not a solid: both sides are seen.
        side: three.DoubleSide,
      });
      disposers.push(() => material.dispose());
      const mesh = new three.Mesh(geometry, material);
      mesh.castShadow = true;
      mesh.receiveShadow = true;
      // On the middle of the floor, so the orbit turns around the part.
      mesh.position.sub(centre);
      mesh.position.y += size.y / 2;
      scene.add(mesh);

      const gl = new three.WebGLRenderer({ antialias: true, alpha: true });
      disposers.push(() => {
        gl.dispose();
        // Give the context back now: a browser holds about sixteen.
        gl.forceContextLoss();
        gl.domElement.remove();
      });
      gl.setPixelRatio(Math.min(window.devicePixelRatio || 1, 2));
      gl.setClearAlpha(0);
      gl.shadowMap.enabled = true;
      // PCFSoftShadowMap is gone since r186.
      gl.shadowMap.type = three.PCFShadowMap;
      gl.toneMapping = three.ACESFilmicToneMapping;
      gl.toneMappingExposure = 0.95;
      gl.domElement.className = "exv-model-canvas";
      root.append(gl.domElement);

      // An environment rather than lamps: a part is read by how its faces
      // catch the light. Rendered once into a cube map, nothing fetched.
      const pmrem = new three.PMREMGenerator(gl);
      const environment = pmrem.fromScene(new RoomEnvironment(), 0.04);
      disposers.push(() => {
        environment.texture.dispose();
        pmrem.dispose();
      });
      scene.environment = environment.texture;
      scene.environmentIntensity = 0.75;

      // One directional light, for the shadow that says where the part sits.
      const sun = new three.DirectionalLight(0xffffff, 1.6);
      sun.position.set(span * 0.8, span * 1.6, span);
      sun.castShadow = true;
      sun.shadow.mapSize.set(2048, 2048);
      const shadowSpan = span * 0.9;
      Object.assign(sun.shadow.camera, { left: -shadowSpan, right: shadowSpan, top: shadowSpan, bottom: -shadowSpan, near: span * 0.1, far: span * 8 });
      // Proportional to the model: a fixed bias is acne in millimetres and a
      // floating shadow in metres.
      sun.shadow.normalBias = span * 0.004;
      scene.add(sun);

      // Shades where the shadow falls and nothing else: the page's own
      // ground shows through the rest.
      const floor = new three.Mesh(new three.PlaneGeometry(span * 12, span * 12), new three.ShadowMaterial({ opacity: 0.22 }));
      disposers.push(() => {
        floor.geometry.dispose();
        floor.material.dispose();
      });
      floor.rotation.x = -Math.PI / 2;
      floor.receiveShadow = true;
      scene.add(floor);

      const camera = new three.PerspectiveCamera(45, 1, span / 100, span * 100);
      camera.position.set(span * 0.9, span * 0.8, span * 1.4);
      const controls = new OrbitControls(camera, gl.domElement);
      disposers.push(() => controls.dispose());
      controls.target.set(0, size.y / 2, 0);
      // Towards what is under the pointer, not the middle of the model.
      controls.zoomToCursor = true;
      controls.enableDamping = true;
      // Under the floor is only the back of the shadow catcher.
      controls.maxPolarAngle = Math.PI / 2 - 0.02;
      controls.update();

      const resize = () => {
        const { clientWidth, clientHeight } = root;
        if (!clientWidth || !clientHeight) return;
        gl.setSize(clientWidth, clientHeight, false);
        camera.aspect = clientWidth / clientHeight;
        camera.updateProjectionMatrix();
      };
      resize();
      const observer = new ResizeObserver(resize);
      observer.observe(root);
      disposers.push(() => observer.disconnect());

      let frame = 0;
      const draw = () => {
        frame = requestAnimationFrame(draw);
        controls.update();
        gl.render(scene, camera);
      };
      draw();
      disposers.push(() => cancelAnimationFrame(frame));

      ctx.status(triangles > 0 ? { phase: "ready" } : { phase: "empty" });
      return {
        controllers: { info: writable({ triangles }), warnings: writable(modelWarnings(model.meta, "stl")) },
        resize,
        destroy: dispose,
      };
    } catch (error) {
      // The worker and the context go now, not when the viewer closes.
      dispose();
      throw error;
    }
  },
};
