from inventory_parser import parse_inventory


def test_parse_inventory_yaml(tmp_path):
    path = tmp_path / "stack.yaml"
    path.write_text(
        """
packages:
  - name: openssl
    version: "3.0.7"
    ecosystem: Debian
  - log4j
""",
        encoding="utf-8",
    )

    items = parse_inventory(path)

    assert items[0].product == "openssl"
    assert items[0].version == "3.0.7"
    assert items[1].product == "log4j"


def test_parse_inventory_applications_yaml(tmp_path):
    path = tmp_path / "stack.yaml"
    path.write_text(
        """
applications:
  - name: nginx
    version: "1.20"
  - package_name: openssl
    version: "1.1.1"
""",
        encoding="utf-8",
    )

    items = parse_inventory(path)

    assert [item.product for item in items] == ["nginx", "openssl"]


def test_parse_inventory_invalid_yaml_raises_clear_error(tmp_path):
    path = tmp_path / "stack.yaml"
    path.write_text("applications:\n  -name: nginx\n   version: '1.20'\n", encoding="utf-8")

    try:
        parse_inventory(path)
    except ValueError as exc:
        assert "Invalid inventory YAML" in str(exc)
    else:
        raise AssertionError("Expected invalid YAML to raise ValueError")
