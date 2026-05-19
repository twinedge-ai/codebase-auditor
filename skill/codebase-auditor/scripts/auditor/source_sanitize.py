from __future__ import annotations


def sanitize_code_lines(text: str) -> list[str]:
    lines: list[str] = []
    current: list[str] = []
    state = "code"
    quote = ""
    template_depth = 0
    index = 0
    while index < len(text):
        char = text[index]
        nxt = text[index + 1] if index + 1 < len(text) else ""

        if char == "\n":
            lines.append("".join(current))
            current = []
            if state == "line_comment":
                state = "code"
            index += 1
            continue

        if state == "code":
            if char == "/" and nxt == "/":
                current.extend("  ")
                state = "line_comment"
                index += 2
                continue
            if char == "/" and nxt == "*":
                current.extend("  ")
                state = "block_comment"
                index += 2
                continue
            if char == "#":
                current.append(" ")
                state = "line_comment"
                index += 1
                continue
            if char in {"'", '"', "`"}:
                quote = char
                current.append(" ")
                state = "string"
                index += 1
                continue
            current.append(char)
            index += 1
            continue

        if state == "string":
            if char == "\\":
                current.extend("  " if nxt else " ")
                index += 2 if nxt else 1
                continue
            if quote == "`" and char == "$" and nxt == "{":
                current.extend("${")
                state = "template_expr"
                template_depth = 1
                index += 2
                continue
            current.append(" ")
            if char == quote:
                state = "code"
            index += 1
            continue

        if state == "template_expr":
            current.append(char)
            if char == "{":
                template_depth += 1
            elif char == "}":
                template_depth -= 1
                if template_depth <= 0:
                    state = "string"
            index += 1
            continue

        if state == "block_comment":
            current.append(" ")
            if char == "*" and nxt == "/":
                current.append(" ")
                state = "code"
                index += 2
            else:
                index += 1
            continue

        current.append(" ")
        index += 1

    lines.append("".join(current))
    return lines
