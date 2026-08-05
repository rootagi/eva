def test_compatibility_reexports():
    import eva.budget
    import eva.cache
    import eva.chat_session
    import eva.cli
    import eva.config
    import eva.context
    import eva.context.finder
    import eva.context.gitignore
    import eva.context.io
    import eva.context.tokenizer
    import eva.context.tree
    import eva.diagnostics
    import eva.git_ops
    import eva.router
    import eva.router.gemini_provider
    import eva.router.groq_provider
    import eva.router.openai_compat
    import eva.router.opencode_zen_provider
    import eva.router.openrouter_provider
    import eva.work_safety

    assert eva.cli.app is not None
    assert eva.config.load_config is not None
    assert eva.work_safety.parse_safe_command is not None
