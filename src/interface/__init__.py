"""
CLI interface module.

Command handlers for init/unlock/list/get/add/edit/remove/lock.
Never accepts secrets as CLI arguments (see docs/DESIGN.md, T12) -
always prompts interactively.
"""
