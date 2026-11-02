"""Conway's Game of Life on a torus, printed as text. CC0-1.0, exav project."""
import random
import sys

WIDTH, HEIGHT = 40, 16


def step(cells):
    """The next generation of a set of (x, y) cells on a WIDTH by HEIGHT torus."""
    counts = {}
    for (x, y) in cells:
        for dx in (-1, 0, 1):
            for dy in (-1, 0, 1):
                if dx or dy:
                    key = ((x + dx) % WIDTH, (y + dy) % HEIGHT)
                    counts[key] = counts.get(key, 0) + 1
    return {cell for cell, n in counts.items() if n == 3 or (n == 2 and cell in cells)}


def show(cells):
    return "\n".join("".join("#" if (x, y) in cells else "." for x in range(WIDTH)) for y in range(HEIGHT))


def main(generations=20, seed=7):
    rng = random.Random(seed)
    cells = {(x, y) for x in range(WIDTH) for y in range(HEIGHT) if rng.random() < 0.25}
    for g in range(generations):
        print(f"generation {g}: {len(cells)} cells")
        print(show(cells))
        cells = step(cells)


if __name__ == "__main__":
    main(*(int(a) for a in sys.argv[1:3]))
