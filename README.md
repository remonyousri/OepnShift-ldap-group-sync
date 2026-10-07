# ldap-group-syncer-v2

CronJob in `openshift-authentication`, every 15 minutes:

1. `oc adm groups sync` for the AD groups in `whitelist.txt` (same as v1).
2. `prune_ldap_users.py`: every OpenShift user from the `NFII` LDAP identity provider whose
   `sAMAccountName` no longer exists in AD is removed, with its group memberships, its
   RoleBindings/ClusterRoleBindings (only those where it is the sole subject), its console
   user-settings Role/ConfigMap, and every Identity pointing at it.
   Stops without deleting anything on any LDAP/API error, or when more than `MAX_DELETE` users
   would go in one run. `DRY_RUN=true` only prints the plan.

Live on non-prod since 2026-10-07 (first cleanup removed 30 users, 31 identities, 58 bindings,
including a `cluster-admin` binding for a deleted user). v1 `ldap-group-syncer` is suspended there.

## Files

| File | What |
|---|---|
| `role.yaml` | ServiceAccount, ClusterRole/Binding (groups; users/identities get/list/delete; role bindings get/list/delete), Role/Binding in `openshift-console-user-settings` |
| `cronjob.yaml` | The CronJob. Ships `suspend: true`, `DRY_RUN=true`, `MAX_DELETE=5` |
| `ldap-group-sync.yaml` | LDAP sync config; password read from the Secret file |
| `whitelist.txt` | AD groups to sync |
| `prune_ldap_users.py` | User cleanup script (plain Python 3, no LDAP libraries needed) |
| `kustomization.yaml` | `oc apply -k .` applies all of the above, building the ConfigMap from the 3 files |

The bind password Secret `ldap-group-syncer-v2-bind` is created by hand (step 3), never stored here.

## Deploy on another cluster (Prod)

Run with `oc` logged into the target cluster (`oc whoami --show-server`).

1. **Check the values match that cluster** and edit the files if not:
   - IdP name and LDAP URL: `oc get oauth cluster -o yaml` (non-prod: `NFII`, `ldap://nfii.com:389`).
     IdP name goes in `IDP_NAME` in `cronjob.yaml`.
   - Bind DN, groups and queries: compare with v1, `oc get cm ldap-group-syncer -n openshift-authentication -o yaml`
     and `oc get cm whitelist -n openshift-authentication -o yaml`.
   - CLI image digest: `oc get is cli -n openshift -o jsonpath='{.status.tags[0].items[0].dockerImageReference}'`
     and put it in `cronjob.yaml`.
2. **Apply** (needs cluster-admin; creates RBAC):
   ```
   oc apply -k .
   ```
3. **Create the password Secret** from v1's config without printing it:
   ```
   oc get cm ldap-group-syncer -n openshift-authentication -o jsonpath='{.data.ldap-group-sync\.yaml}' \
     | sed -n 's/^bindPassword:[[:space:]]*//p' | sed -e 's/^["'\'']//' -e 's/["'\'']$//' | tr -d '\n' > .bindpw \
     && chmod 600 .bindpw \
     && oc create secret generic ldap-group-syncer-v2-bind -n openshift-authentication --from-file=bindPassword=.bindpw; rm -f .bindpw
   ```
4. **Dry run** and read the plan (expect `ABORT: N users exceeds MAX_DELETE=5` if N > 5, the plan prints first):
   ```
   oc create job ldap-group-syncer-v2-dryrun -n openshift-authentication --from=cronjob/ldap-group-syncer-v2
   oc logs -n openshift-authentication job/ldap-group-syncer-v2-dryrun
   ```
   Review every user and binding. Exclude anyone who must stay with `EXCLUDE_USERS` (comma-separated):
   `oc set env cronjob/ldap-group-syncer-v2 -n openshift-authentication EXCLUDE_USERS=user1,user2`
5. **One-time cleanup** (set `MAX_DELETE` to the user count from step 4):
   ```
   oc set env cronjob/ldap-group-syncer-v2 -n openshift-authentication DRY_RUN=false MAX_DELETE=<N>
   oc patch cronjob ldap-group-syncer-v2 -n openshift-authentication -p '{"spec":{"jobTemplate":{"spec":{"activeDeadlineSeconds":1800}}}}'
   oc create job ldap-group-syncer-v2-cleanup -n openshift-authentication --from=cronjob/ldap-group-syncer-v2
   oc logs -f -n openshift-authentication job/ldap-group-syncer-v2-cleanup
   ```
6. **Go live** and retire v1:
   ```
   oc set env cronjob/ldap-group-syncer-v2 -n openshift-authentication MAX_DELETE=5
   oc patch cronjob ldap-group-syncer-v2 -n openshift-authentication -p '{"spec":{"suspend":false,"jobTemplate":{"spec":{"activeDeadlineSeconds":300}}}}'
   oc patch cronjob ldap-group-syncer -n openshift-authentication -p '{"spec":{"suspend":true}}'
   ```
   After v2 has run cleanly for a while, delete v1 and its ConfigMap (it holds the password in plain text).

## Changing an already-live cluster

`oc apply -k .` resets the CronJob to suspended + dry-run. On a live cluster reload only the ConfigMap:
```
oc create configmap ldap-group-syncer-v2 -n openshift-authentication --from-file=ldap-group-sync.yaml \
  --from-file=whitelist.txt --from-file=prune_ldap_users.py --dry-run=client -o yaml | oc apply -f -
```

## Known limits

- LDAP is plain `ldap://389`: the AD certificate on 636 is rejected by RHEL 9 (key too weak).
  Once AD has a stronger certificate, switch both v2 and the OAuth IdP to `ldaps://`.
- A RoleBinding shared with an active user or service account is reported (`! shared binding left alone`)
  and must be cleaned by hand; the job only deletes bindings, it cannot edit them.
- Deleted users' personal projects (for example `chambersch-test`, `naresh-test1`) are left in place.
