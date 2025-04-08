from pathlib import Path

file_paths = [
    "subprojects/rzwinkd/iob_net.c",
    "librz/debug/p/native/linux/linux_debug.c",
    "librz/debug/trace.c",
    "librz/include/rz_core.h",
    "librz/include/rz_util/rz_annotated_code.h",
    "librz/include/rz_util/rz_spaces.h",
    "librz/include/rz_util/rz_graph_drawable.h",
    "librz/include/rz_project.h",
    "librz/config/serialize_config.c",
    "librz/bin/dwarf.c",
    "librz/bin/p/bin_qnx.c",
    "librz/analysis/p/analysis_x86_cs.c",
    "librz/analysis/class.c",
    "librz/analysis/rtti_itanium.c",
    "librz/core/cannotated_code.c"
]

def update_param_tags(file_path):
    try:
        file = Path(file_path)
        if not file.exists():
            print(f"❌ File not found: {file_path}")
            return

        lines = file.read_text().splitlines()
        modified = False

        updated_lines = []
        for line in lines:
            if "@param" in line:
                line = line.replace("@param", r"\param")
                modified = True
            updated_lines.append(line)

        if modified:
            file.write_text("\n".join(updated_lines) + "\n")
            print(f"✅ Updated: {file_path}")
        else:
            print(f"➖ No changes: {file_path}")

    except Exception as e:
        print(f"❌ Error processing {file_path}: {e}")

# Run on all files
for path in file_paths:
    update_param_tags(path)