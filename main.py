import os

to_search = []
for key_type in (0, 1):
    for dc_id in (1, 2, 3, 4, 5):
        to_search.append(bytes([key_type, 0, 0, 0, dc_id, 0, 0, 0]))

with open("/proc/2270/maps", "r") as f:
    maps = f.read().splitlines(False)

for idx, map_ in enumerate(maps):
    while "  " in map_:
        map_ = map_.replace("  ", " ")
    maps[idx] = map_.split(" ")

maps = list(filter(lambda m: m[4] == "0", maps))

addresses = []
for map_ in maps:
    start, end = map_[0].split("-")
    start = int(start, 16)
    end = int(end, 16)
    print(f"map {hex(start)}-{hex(end)}: len={end-start}")
    addresses.append((start, end))

addresses.sort(key=lambda a: a[0])

with open("/proc/2270/mem", "rb") as f:
    for idx, (start, end) in enumerate(addresses):
        try:
            f.seek(start, os.SEEK_SET)
        except ValueError:
            continue

        print(f"Reading {end-start} bytes at {hex(start)}")

        try:
            data = f.read(end-start)
        except OSError as e:
            print(e)
            continue

        for bytes_to_search in to_search:
            ...

