# eva-plugin-hello

An example plugin for [Eva CLI](https://github.com/rootagi/eva).

## Usage

Install in editable mode or as a package:

```bash
pip install -e .
```

Once installed, Eva CLI will automatically discover the plugin via entry points and register the `eva hello` command:

```bash
eva hello
# Hello, World! (from eva-hello plugin)

eva hello Alice
# Hello, Alice! (from eva-hello plugin)
```
