package util

import rego.v1

# Transform OPA coverage report into the Coveralls source_files format.
from_opa := {"source_files": file_entries}

file_entries contains entry if {
	some filepath, report in input.files
	entry := {"name": filepath, "coverage": generate_line_data(report)}
}

# Build a map of lines that were executed (value 1).
build_covered_map(report) := cmap if {
	hit_lines := object.get(report, "covered", [])
	cmap := {ln: 1 |
		some span in hit_lines
		some ln in numbers.range(span.start.row, span.end.row)
	}
}

# Build a map of lines that were not executed (value 0).
build_uncovered_map(report) := umap if {
	missed_lines := object.get(report, "not_covered", [])
	umap := {ln: 0 |
		some span in missed_lines
		some ln in numbers.range(span.start.row, span.end.row)
	}
}

# Produce an array of coverage values (1, 0, or null) for each line up to the last known line.
generate_line_data(report) := result if {
	cmap := build_covered_map(report)
	umap := build_uncovered_map(report)
	all_lines := sort([ln | some ln, _ in object.union(cmap, umap)])
	max_line := all_lines[count(all_lines) - 1]

	result := [line_status(cmap, umap, idx) |
		some idx in numbers.range(1, max_line)
	]
}

# A line that was covered gets value 1.
line_status(cmap, _, ln) := 1 if {
	cmap[ln]
}

# A line that was not covered gets value 0.
line_status(_, umap, ln) := 0 if {
	umap[ln]
}

# Lines with no coverage data at all get null.
line_status(cmap, umap, ln) := null if {
	not cmap[ln]
	not umap[ln]
}
