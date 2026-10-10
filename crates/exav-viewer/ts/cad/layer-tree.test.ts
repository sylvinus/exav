import { describe, expect, it } from 'vitest'
import { buildLayerTree, layerIndicesIn, type LayerTreeNode } from './layer-tree'
import type { Layer } from './types'

function mk(names: string[]): Layer[] {
  return names.map((name) => ({
    name,
    color: 0xffffffff,
    lineweight: 0,
    off: false,
    frozen: false,
    visible: true,
  }))
}

function labels(nodes: LayerTreeNode[]): string[] {
  return nodes.map((n) => (n.kind === 'group' ? `${n.label}/` : n.label))
}

function allLeafNames(nodes: LayerTreeNode[], layers: Layer[]): string[] {
  return nodes.flatMap(layerIndicesIn).map((i) => layers[i].name)
}

describe('buildLayerTree', () => {
  it('keeps every layer exactly once', () => {
    // An architect's layer list, numbered by discipline, messy entries included.
    const names = [
      '0',
      'Defpoints',
      '00_ALTIMETRIES',
      '00_AXES',
      '01_PM_BATI',
      '01_PM_RESEAUX EAU',
      '03_GO_MACONNERIE',
      '03_GO_METAL',
      'LIMITES',
      '$$NV PROJET',
      '3',
    ]
    const layers = mk(names)
    const tree = buildLayerTree(layers)
    const seen = allLeafNames(tree, layers)
    expect(seen.sort()).toEqual([...names].sort())
  })

  it('groups a shared discipline prefix', () => {
    const layers = mk(['03_GO_BOIS', '03_GO_MACONNERIE', '03_GO_METAL'])
    const tree = buildLayerTree(layers)
    expect(tree).toHaveLength(1)
    expect(tree[0].kind).toBe('group')
    if (tree[0].kind === 'group') {
      expect(tree[0].children).toHaveLength(3)
      expect(labels(tree[0].children).sort()).toEqual(['BOIS', 'MACONNERIE', 'METAL'])
    }
  })

  it('collapses a single-child chain into one row', () => {
    // `03` has only `GO` beneath it, so the tree should not make the user
    // expand twice to reach anything.
    const layers = mk(['03_GO_BOIS', '03_GO_METAL'])
    const tree = buildLayerTree(layers)
    expect(tree).toHaveLength(1)
    if (tree[0].kind === 'group') {
      expect(tree[0].path).toBe('03_GO_')
      expect(tree[0].children.every((c) => c.kind === 'layer')).toBe(true)
    }
  })

  it('leaves an unprefixed layer at the top level', () => {
    const layers = mk(['03_GO_BOIS', '03_GO_METAL', 'LIMITES'])
    const tree = buildLayerTree(layers)
    const top = labels(tree)
    expect(top).toContain('LIMITES')
    // LIMITES must not be swallowed into the 03 group.
    const group = tree.find((n) => n.kind === 'group')
    expect(group && layerIndicesIn(group)).toHaveLength(2)
  })

  it('does not group a lone prefixed layer', () => {
    const layers = mk(['09_ELEC', 'LIMITES', 'RENDU'])
    const tree = buildLayerTree(layers)
    expect(tree.every((n) => n.kind === 'layer')).toBe(true)
  })

  it('splits xref layers on the pipe namespace', () => {
    const layers = mk([
      'Site_Xref_Cartouche A3|00_SURFACE_CONTOUR',
      'Site_Xref_Cartouche A1|00_SURFACE_CONTOUR',
      'Site_Xref_Cartouche A1|Surfaces',
    ])
    // Pipe is a real namespace, so it must win over the underscore convention.
    const tree = buildLayerTree(layers, { separators: ['|'], maxDepth: 1 })
    expect(tree).toHaveLength(2)
    const a1 = tree.find((n) => n.kind === 'group' && n.label.endsWith('A1'))
    expect(a1).toBeDefined()
    if (a1 && a1.kind === 'group') expect(a1.children).toHaveLength(2)
  })

  it('strips the group prefix from child labels', () => {
    const layers = mk(['15_TX_100', '15_TX_200', '15_TX_500'])
    const tree = buildLayerTree(layers)
    if (tree[0].kind === 'group') {
      expect(labels(tree[0].children).sort()).toEqual(['100', '200', '500'])
    }
  })

  it('honours maxDepth', () => {
    const layers = mk(['01_PM_BATI', '01_PM_VOIRIE', '01_XX_OTHER', '01_XX_MORE'])
    const flat = buildLayerTree(layers, { maxDepth: 1 })
    expect(flat).toHaveLength(1)
    if (flat[0].kind === 'group') {
      // Depth 1 stops at `01`, so all four sit directly underneath.
      expect(flat[0].children.every((c) => c.kind === 'layer')).toBe(true)
      expect(flat[0].children).toHaveLength(4)
    }
  })

  it('returns a flat list when given no separators', () => {
    const layers = mk(['03_GO_BOIS', '03_GO_METAL'])
    const tree = buildLayerTree(layers, { separators: [] })
    expect(tree.every((n) => n.kind === 'layer')).toBe(true)
    expect(labels(tree)).toEqual(['03_GO_BOIS', '03_GO_METAL'])
  })

  it('handles an empty layer list', () => {
    expect(buildLayerTree([])).toEqual([])
  })

  it('handles names that are only separators', () => {
    const layers = mk(['_', '__', '0'])
    const tree = buildLayerTree(layers)
    expect(allLeafNames(tree, layers).sort()).toEqual(['0', '_', '__'])
  })

  it('scales to a realistic sheet without losing layers', () => {
    const names = [
      '0', 'Defpoints', '00_ALTIMETRIES', '00_ALTIMETRIES_COTES', '00_AXES',
      '00_AXES_COTES', '00_HACHURES', '00_SURFACE_CONTOUR', '00_TRAIT_COUPE',
      '01_PM_BATI', '01_PM_BATI_HACHURES_PROJET', '01_PM_LIMITE PARCELLE_CONTEXTE',
      '01_PM_RESEAUX EAU', '01_PM_RESEAUX ELEC', '01_PM_RESEAUX GAZ',
      '01_PM_VEGETATION', '01_PM_VOIRIE', '02_DC_DIAGNOSTIC', '02_DC_DEMOLITION',
      '03_GO_BOIS', '03_GO_MACONNERIE', '03_GO_METAL', '03_GO_PROJETE',
      '15_TX_010', '15_TX_020', '15_TX_050', '16_CO_010', '16_CO_020',
      '17_COULEUR 1', '17_COULEUR 2', 'LIMITES', 'RENDU', 'Talus', '3', '7', '8',
    ]
    const layers = mk(names)
    const tree = buildLayerTree(layers)
    expect(allLeafNames(tree, layers).sort()).toEqual([...names].sort())
    // The messy tail should stay visible at the top rather than hiding in a group.
    expect(labels(tree)).toEqual(expect.arrayContaining(['LIMITES', 'RENDU', 'Talus']))
    // And the disciplines should have collapsed into groups.
    expect(tree.filter((n) => n.kind === 'group').length).toBeGreaterThanOrEqual(4)
  })
})

describe('ordering', () => {
  it('puts groups before loose layers', () => {
    // Loose names come first in the source order; they must not stay there,
    // or the structured layers get buried below a wall of one-offs.
    const layers = mk(['0', 'Defpoints', 'LIMITES', '03_GO_BOIS', '03_GO_METAL'])
    const tree = buildLayerTree(layers)
    expect(tree[0].kind).toBe('group')
    expect(tree.slice(1).every((n) => n.kind === 'layer')).toBe(true)
  })

  it('sorts numeric suffixes naturally', () => {
    const layers = mk(['15_TX_020', '15_TX_100', '15_TX_010'])
    const tree = buildLayerTree(layers)
    if (tree[0].kind === 'group') {
      expect(tree[0].children.map((c) => c.label)).toEqual(['010', '020', '100'])
    }
  })

  it('sorts groups among themselves', () => {
    const layers = mk(['15_TX_A', '15_TX_B', '03_GO_A', '03_GO_B'])
    const tree = buildLayerTree(layers)
    expect(tree.map((n) => n.label)).toEqual(['03_GO', '15_TX'])
  })
})
