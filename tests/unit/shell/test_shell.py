from eva.shell import execute_shell_command


def test_execute_shell_command():
    res = execute_shell_command("echo hello_shell")
    assert res.returncode == 0
    assert "hello_shell" in res.stdout
