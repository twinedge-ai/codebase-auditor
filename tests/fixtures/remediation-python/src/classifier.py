def keep_actionable(statuses):
    actionable = []
    for status in statuses:
        if status in ["draft", "pending", "queued", "blocked"]:
            actionable.append(status)
    return actionable
