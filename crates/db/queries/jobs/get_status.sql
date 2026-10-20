-- class: infra. params: id
SELECT status, attempts FROM jobs WHERE id = ?
