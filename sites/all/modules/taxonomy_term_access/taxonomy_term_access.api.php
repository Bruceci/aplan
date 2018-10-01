<?php

/**
 * @file
 * Hooks provided by the Taxonomy term access module.
 */

/**
 * @addtogroup hooks
 * @{
 */

/**
 * Inform the taxonomy term access system what permissions the user has.
 *
 * This hook is for implementation by taxonomy term access modules. In this
 * hook, the module grants a user different "grant IDs" within one or more
 * "realms". In hook_taxonomy_term_access_records(), the realms and grant IDs
 * are associated with permission to view, edit, and delete individual taxonomy
 * terms.
 *
 * The realms and grant IDs can be arbitrarily defined by your taxonomy term
 * access module; it is common to use role IDs as grant IDs, but that is not
 * required. Your module could instead maintain its own list of users, where
 * each list has an ID. In that case, the return value of this hook would be an
 * array of the list IDs of which this user is a member.
 *
 * A taxonomy term access module may implement as many realms as necessary to
 * define properly the access privileges for the taxonomy terms.
 *
 * Taxonomy term access records are stored in the {taxonomy_term_access} table
 * and define which grants are required to access a term. There is a special
 * case for the view operation -- a record with term ID 0 corresponds to a
 * "view all" grant for the realm and grant ID of that record. If there are no
 * taxonomy term access modules enabled, this taxonomy term access module adds a
 * term ID 0 record for realm 'all'. Taxonomy term access modules can also grant
 * "view all" permission on their custom realms; for example, a module could
 * create a record in {taxonomy_term_access} with:
 * @code
 * $record = array(
 *   'tid' => 0,
 *   'gid' => 888,
 *   'realm' => 'example_realm',
 *   'grant_view' => 1,
 *   'grant_update' => 0,
 *   'grant_delete' => 0,
 * );
 * drupal_write_record('taxonomy_term_access', $record);
 * @endcode
 * And then in its hook_taxonomy_term_grants() implementation, it would need to
 * return:
 * @code
 * if ($op == 'view') {
 *   $grants['example_realm'] = array(888);
 * }
 * @endcode
 * If you decide to do this, be aware that the taxonomy_term_access_rebuild()
 * function will erase any term ID 0 entry when it is called, so you will need
 * to make sure to restore your {taxonomy_term_access} record after
 * taxonomy_term_access_rebuild() is called.
 *
 * @see taxonomy_term_access_view_all_taxonomy_terms()
 * @see taxonomy_term_access_rebuild()
 *
 * @param object $account
 *   The user object whose grants are requested.
 * @param string $op
 *   The term operation to be performed, such as 'view', 'update', or 'delete'.
 *
 * @return array
 *   An array whose keys are "realms" of grants, and whose values are arrays of
 *   the grant IDs within this realm that this user is being granted.
 *
 * @ingroup taxonomy_term_access
 */
function hook_taxonomy_term_grants($account, $op) {
  if (user_access('access private terms', $account)) {
    $grants['example'] = array(1);
  }
  $grants['example_author'] = array($account->uid);
  return $grants;
}

/**
 * Set permissions for a taxonomy term to be written to the database.
 *
 * When a taxonomy term is saved, a module implementing
 * hook_taxonomy_term_access_records() will be asked if it is interested in the
 * access permissions for a taxonomy term. If it is interested, it must respond
 * with an array of permissions arrays for that taxonomy term.
 *
 * Note that the grant values in the return value from your hook must be
 * integers and not boolean TRUE and FALSE.
 *
 * Each permissions item in the array is an array with the following elements:
 * - 'realm': The name of a realm that the module has defined in
 *   hook_taxonomy_term_grants().
 * - 'gid': A 'grant ID' from hook_taxonomy_term_grants().
 * - 'grant_view': If set to 1 a user that has been identified as a member
 *   of this gid within this realm can view this taxonomy term.
 * - 'grant_update': If set to 1 a user that has been identified as a member
 *   of this gid within this realm can edit this taxonomy term.
 * - 'grant_delete': If set to 1 a user that has been identified as a member
 *   of this gid within this realm can delete this taxonomy term.
 * - 'priority': If multiple modules seek to set permissions on a taxonomy term,
 *   the realms that have the highest priority will win out, and realms with a
 *   lower priority will not be written. If there is any doubt, it is best to
 *   leave this 0.
 *
 * When an implementation is interested in a taxonomy term but want to deny
 * access to everyone, it may return a "deny all" grant:
 *
 * @code
 * $grants[] = array(
 *   'realm' => 'all',
 *   'gid' => 0,
 *   'grant_view' => 0,
 *   'grant_update' => 0,
 *   'grant_delete' => 0,
 *   'priority' => 1,
 * );
 * @endcode
 *
 * Setting the priority should cancel out other grants. In the case of a
 * conflict between modules, it is safer to use
 * hook_taxonomy_term_access_records_alter() to return only the deny grant.
 *
 * Note: a deny all grant is not written to the database; denies are implicit.
 *
 * @see taxonomy_term_access_write_grants()
 *
 * @param object $term
 *   The taxonomy term that has just been saved.
 *
 * @return array
 *   An array of grants as defined above.
 *
 * @see hook_taxonomy_term_access_records_alter()
 * @ingroup taxonomy_term_access
 */
function hook_taxonomy_term_access_records($term) {
  // We care about the taxonomy term only if it has been marked private. If not,
  // it is treated just like any other taxonomy term and we completely ignore
  // it.
  if ($term->private) {
    $grants = array();
    // For the example_author array, the GID is equivalent to a UID, which
    // means there are many groups of just 1 user.
    // Note that an author can always view his or her taxonomy terms.
    $grants[] = array(
      'realm' => 'example_author',
      'gid' => $term->uid,
      'grant_view' => 1,
      'grant_update' => 1,
      'grant_delete' => 1,
      'priority' => 0,
    );

    return $grants;
  }
}

/**
 * Alter permissions for a taxonomy term before it is written to the database.
 *
 * Taxonomy term access modules establish rules for user access to terms.
 * Taxonomy term access records are stored in the {taxonomy_term_access} table
 * and define which permissions are required to access a taxonomy term. This
 * hook is invoked after taxonomy term access modules returned their
 * requirements via hook_taxonomy_term_access_records(); doing so allows modules
 * to modify the $grants array by reference before it is stored, so custom or
 * advanced business logic can be applied.
 *
 * @see hook_taxonomy_term_access_records()
 *
 * Upon viewing, editing or deleting a taxonomy term,
 * hook_taxonomy_term_grants() builds a permissions array that is compared
 * against the stored access records. The user must have one or more matching
 * permissions in order to complete the requested operation.
 *
 * A module may deny all access to a taxonomy term by setting $grants to an
 * empty array.
 *
 * @see hook_taxonomy_term_grants()
 * @see hook_taxonomy_term_grants_alter()
 *
 * @param array $grants
 *   The $grants array returned by hook_taxonomy_term_access_records().
 * @param object $term
 *   The taxonomy term for which the grants were acquired.
 *
 * The preferred use of this hook is in a module that bridges multiple taxonomy
 * term access modules with a configurable behavior, as shown in the example
 * with the 'is_preview' field.
 *
 * @ingroup taxonomy_term_access
 */
function hook_taxonomy_term_access_records_alter(array &$grants, $term) {
  // Our module allows editors to mark specific terms with the 'is_preview'
  // field. If the taxonomy term being saved has a TRUE value for that field,
  // then only our grants are retained, and other grants are removed. Doing so
  // ensures that our rules are enforced no matter what priority other grants
  // are given.
  if ($term->is_preview) {
    // Our module grants are set in $grants['example'].
    $temp = $grants['example'];
    // Now remove all module grants but our own.
    $grants = array('example' => $temp);
  }
}

/**
 * Alter user access rules when trying to view, edit or delete a taxonomy term.
 *
 * Taxonomy term access modules establish rules for user access to terms.
 * hook_taxonomy_term_grants() defines permissions for a user to view, edit or
 * delete taxonomy terms by building a $grants array that indicates the
 * permissions assigned to the user by each taxonomy term access module. This
 * hook is called to allow modules to modify the $grants array by reference, so
 * the interaction of multiple taxonomy term access modules can be altered or
 * advanced business logic can be applied.
 *
 * @see hook_taxonomy_term_grants()
 *
 * The resulting grants are then checked against the records stored in the
 * {taxonomy_term_access} table to determine if the operation may be completed.
 *
 * A module may deny all access to a user by setting $grants to an empty array.
 *
 * @see hook_taxonomy_term_access_records()
 * @see hook_taxonomy_term_access_records_alter()
 *
 * @param array $grants
 *   The $grants array returned by hook_taxonomy_term_grants().
 * @param object $account
 *   The user account requesting access to terms.
 * @param string $op
 *   The operation being performed, 'view', 'update' or 'delete'.
 *
 * Developers may use this hook either to add additional grants to a user or to
 * remove existing grants. These rules are typically based on either the
 * permissions assigned to a user role, or specific attributes of a user
 * account.
 *
 * @ingroup taxonomy_term_access
 */
function hook_taxonomy_term_grants_alter(array &$grants, $account, $op) {
  // Our sample module never allows certain roles to edit or delete
  // terms. Since some other taxonomy term access modules might allow this
  // permission, we expressly remove it by returning an empty $grants
  // array for roles specified in our variable setting.

  // Get our list of banned roles.
  $restricted = variable_get('example_restricted_roles', array());

  if ($op != 'view' && !empty($restricted)) {
    // Now check the roles for this account against the restrictions.
    foreach ($restricted as $role_id) {
      if (isset($account->roles[$role_id])) {
        $grants = array();
      }
    }
  }
}

/**
 * Control access to a taxonomy term.
 *
 * Modules may implement this hook if they want to have a say in whether or not
 * a given user has access to perform a given operation on a taxonomy term.
 *
 * The administrative account (user ID #1) always passes any access check, so
 * this hook is not called in that case. Users with the "bypass term access"
 * permission may always view and edit terms through the administrative
 * interface.
 *
 * Note that not all modules will want to influence access on all vocabularies.
 * If your module does not want to actively grant or block access, return
 * TAXONOMY_TERM_ACCESS_IGNORE or simply return nothing. Blindly returning FALSE
 * will break other taxonomy term access modules.
 *
 * Also note that this function isn't called for taxonomy term listings.
 *
 * @param object $term
 *   Either a taxonomy term object or the machine name of the vocabulary on
 *   which to perform the access check.
 * @param string $op
 *   The operation to be performed. Possible values:
 *   - "create"
 *   - "delete"
 *   - "update"
 *   - "view"
 * @param object $account
 *   The user object to perform the access check operation on.
 *
 * @return int|null
 *   - TAXONOMY_TERM_ACCESS_ALLOW: if the operation is to be allowed.
 *   - TAXONOMY_TERM_ACCESS_DENY: if the operation is to be denied.
 *   - TAXONOMY_TERM_ACCESS_IGNORE: to not affect this operation at all.
 *
 * @ingroup taxonomy_term_access
 */
function hook_taxonomy_term_access($term, $op, $account) {
  $type = is_string($term) ? $term : $term->type;

  if ($op == 'create' && user_access('create ' . $type . ' terms', $account)) {
    return TAXONOMY_TERM_ACCESS_ALLOW;
  }

  if ($op == 'update') {
    if (user_access('edit any ' . $type . ' terms', $account) || (user_access('edit own ' . $type . ' terms', $account) && ($account->uid == $term->uid))) {
      return TAXONOMY_TERM_ACCESS_ALLOW;
    }
  }

  if ($op == 'delete') {
    if (user_access('delete any ' . $type . ' terms', $account) || (user_access('delete own ' . $type . ' termterms', $account) && ($account->uid == $term->uid))) {
      return TAXONOMY_TERM_ACCESS_ALLOW;
    }
  }

  // Returning nothing from this function would have the same effect.
  return TAXONOMY_TERM_ACCESS_IGNORE;
}

/**
 * @} End of "addtogroup hooks".
 */
