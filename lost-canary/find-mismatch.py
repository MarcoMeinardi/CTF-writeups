from systrack.elf import ELF
elf = ELF("lost_canary")
stations = [elf.read_symbol(f"station_{i}") for i in range(0x8000)]

classes = [
	[0, 1, 10002, 10004],        # fgets
	[10, 100, 10010, 10012],     # gets
	[1000, 10001, 10003, 10008]  # scanf
]

def get_classes(class_inds):
	functions_bytes = [stations[i] for i in class_inds]
	always_same = [a == b == c == d for a, b, c, d in zip(*functions_bytes)]
	return functions_bytes[0], always_same

def match(function, reference_arr, always_same_arr):
	for ind, (ref, always_same) in enumerate(zip(reference_arr, always_same_arr)):
		if all(not always_same[i] or function[i] == ref[i] for i in range(len(ref))):
			return ind
	return -1

reference_arr, always_same_arr = zip(*[get_classes(class_) for class_ in classes])

canaries = [elf.read_symbol(f"__stack_chk_guard_{i}") for i in range(0x8000)]
stop_chars = [b"\x00\n", b"\n", b" \n\t\r"]

for i in range(0x8000):
	class_ = match
	class_ = match(stations[i], reference_arr, always_same_arr)
	assert class_ != -1
	canary = canaries[i]

	if all(bytes([b]) not in canary for b in stop_chars[class_]):
		print(f"Canary mismatch for station_{i} ({canary})")
