"""Model Context Protocol surface for Sentinel Arena.

Lets any MCP client (Claude, an IDE, another agent) drive assessments and read
the results. The surface is deliberately *orchestration + reporting only*: it
can list scenarios/agents, issue an ownership challenge for a target, and run a
campaign that returns a prioritized remediation plan. It exposes **no** attack
primitive - every run goes through the same authorization gate and sandbox as
the CLI, and an external target is refused until ownership is proven.
"""
