import argparse
import hashlib
import os
import platform
from typing import Generator

to_search = [
   bytes([key_type, 0, 0, 0, dc_id, 0, 0, 0])
    for key_type in (0, 1)
    for dc_id in (1, 2, 3, 4, 5)
]

_BYTES_TO_SEARCH_LEN = len(to_search[0])
_KEY_LEN = 256
_KEYID_LEN = 8


def _list_processes(name: str = "") -> list[tuple[int, str]]:
    # TODO: add windows support

    processes = []

    for pid in os.listdir("/proc"):
        if not pid.isdigit():
            continue

        try:
            exe_path = os.readlink(f"/proc/{pid}/exe")
        except (PermissionError, FileNotFoundError):
            continue

        if name in exe_path:
            processes.append((int(pid), exe_path))

    return processes


def _get_process_name(pid: int) -> str | None:
    # TODO: add windows support

    try:
        return os.readlink(f"/proc/{pid}/exe")
    except (PermissionError, FileNotFoundError):
        return None


def _find_keys(pid: int, progress: bool) -> Generator[tuple[int, bytes], None, None]:
    # TODO: add windows support

    maps = []

    with open(f"/proc/{pid}/maps", "r") as f:
        maps_data = f.read()

    for map_ in maps_data.splitlines():
        while "  " in map_:
            map_ = map_.replace("  ", " ")
        maps.append(map_.split(" "))

    # Not memory-mapped files (e.g. libs)
    maps = list(filter(lambda m: m[4] == "0", maps))

    addresses = []
    total_size = 0
    for map_ in maps:
        start, end = map_[0].split("-")
        start = int(start, 16)
        end = int(end, 16)
        size = end - start
        addresses.append((start, end))
        total_size += size

    addresses.sort(key=lambda a: a[0])

    read_bytes = 0
    with open(f"/proc/{pid}/mem", "rb") as f:
        for start, end in addresses:
            size = end - start
            read_bytes += size

            try:
                f.seek(start, os.SEEK_SET)
            except ValueError:
                continue

            if progress:
                print(f"Reading {size} bytes at {hex(start)} ({read_bytes / total_size * 100:.2f}%)")

            try:
                # TODO: dont read whole region at once, read smaller chunks (1mb each)
                data = f.read(size)
            except OSError as e:
                #print(e)
                continue

            for bytes_to_search in to_search:
                start = 0
                while True:
                    try:
                        start = data.index(
                            bytes_to_search,
                            start,
                            len(data) - _BYTES_TO_SEARCH_LEN - _KEY_LEN - _KEYID_LEN,
                        )
                    except ValueError:
                        break

                    key_offset = start + _BYTES_TO_SEARCH_LEN
                    keyid_offset = key_offset + _KEY_LEN

                    key = data[key_offset:key_offset + _KEY_LEN]
                    key_id = int.from_bytes(data[keyid_offset:keyid_offset + _KEYID_LEN], "little", signed=True)

                    if b"\x00" * 3 in key:
                        start += _BYTES_TO_SEARCH_LEN
                        continue

                    maybe_key_id = int.from_bytes(hashlib.sha1(key).digest()[-8:], "little", signed=True)
                    if key_id == maybe_key_id:
                        yield bytes_to_search[4], key

                    start += _BYTES_TO_SEARCH_LEN


def main() -> None:
    system = platform.system()
    if system != "Linux":
        print(f"\"{system}\" os is not supported at the moment.")
        exit(1)

    parser = argparse.ArgumentParser()
    parser.add_argument("--pid", "-p", type=int, default=None)
    parser.add_argument("--process-name", "-n", type=str, default="telegram-desktop")
    parser.add_argument("--progress", "-r", action="store_true", default=False)
    args = parser.parse_args()

    processes = []
    if args.pid is not None:
        name = _get_process_name(args.pid)
        if name is not None:
            processes.append((args.pid, name))
    elif args.process_name is not None:
        processes = _list_processes(args.process_name)

    if not processes:
        print("No processes found.")
        exit(1)

    for pid, name in processes:
        print(f"Checking process \"{name}\" (pid {pid})...")
        for dc_id, key in _find_keys(pid, args.progress):
            print(f"DC: {dc_id}, Key: {key.hex()}")


if __name__ == "__main__":
    main()
