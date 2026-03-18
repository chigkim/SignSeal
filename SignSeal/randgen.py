import argparse
import os
from typing import Final

SIZE_UNITS: Final[dict[str, int]] = {
    "b": 1,
    "kb": 1024,
    "mb": 1024**2,
    "gb": 1024**3,
}

DEFAULT_CHUNK_SIZE: Final[int] = 1024 * 1024


def size_to_bytes(value: float, unit: str) -> int:
    unit = unit.lower()
    if unit not in SIZE_UNITS:
        valid = ", ".join(SIZE_UNITS.keys())
        raise ValueError(f"invalid unit: {unit!r}. valid units: {valid}")
    if value < 0:
        raise ValueError("size value must be non-negative")
    return int(value * SIZE_UNITS[unit])


def generate_random_file(
    path: str,
    value: float,
    unit: str = "mb",
    chunk_size: int = DEFAULT_CHUNK_SIZE,
) -> int:
    if chunk_size <= 0:
        raise ValueError("chunk_size must be greater than 0")

    total_bytes = size_to_bytes(value, unit)
    written = 0

    with open(path, "wb") as f:
        while written < total_bytes:
            remaining = total_bytes - written
            this_chunk = min(chunk_size, remaining)
            f.write(os.urandom(this_chunk))
            written += this_chunk

    return total_bytes


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Generate a file containing random binary data."
    )
    parser.add_argument("filename", help="output file path")
    parser.add_argument(
        "value",
        type=float,
        help="numeric size value, for example: 1, 10, 1.5",
    )
    parser.add_argument(
        "unit",
        choices=sorted(SIZE_UNITS.keys()),
        help="size unit: b, kb, mb, or gb",
    )
    parser.add_argument(
        "--chunk-size",
        type=int,
        default=DEFAULT_CHUNK_SIZE,
        help="write chunk size in bytes (default: 1048576)",
    )
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    try:
        total_bytes = generate_random_file(
            path=args.filename,
            value=args.value,
            unit=args.unit,
            chunk_size=args.chunk_size,
        )
    except (OSError, ValueError) as e:
        parser.exit(1, f"error: {e}\n")

    print(f"Created {args.filename} ({total_bytes} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
