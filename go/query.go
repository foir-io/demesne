package demesne

import "context"

// QueryIDs runs query and returns the one column each row holds, as text.
func QueryIDs(ctx context.Context, q Querier, query string, args ...any) ([]string, error) {
	rows, err := q.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// QueryAssignments runs a holds resolver's assignments query for principalID and reads each row: scopeLen scope
// cells, NULL read as empty, then the role key, then the role's permissions when withPermissions is set.
func QueryAssignments(ctx context.Context, q Querier, query, principalID string, scopeLen int, withPermissions bool) ([]RoleAssignment, error) {
	rows, err := q.QueryContext(ctx, query, principalID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []RoleAssignment{}
	for rows.Next() {
		cells := make([]*string, scopeLen)
		dest := make([]any, 0, scopeLen+2)
		for i := range cells {
			dest = append(dest, &cells[i])
		}
		var a RoleAssignment
		var perms TextArray
		dest = append(dest, &a.RoleKey)
		if withPermissions {
			dest = append(dest, &perms)
		}
		if err := rows.Scan(dest...); err != nil {
			return nil, err
		}
		a.Scope = make([]string, scopeLen)
		for i, c := range cells {
			if c != nil {
				a.Scope[i] = *c
			}
		}
		a.Permissions = append([]string{}, perms...)
		out = append(out, a)
	}
	return out, rows.Err()
}
