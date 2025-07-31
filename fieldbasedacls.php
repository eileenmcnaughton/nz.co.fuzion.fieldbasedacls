<?php

require_once 'fieldbasedacls.civix.php';
use CRM_Fieldbasedacls_ExtensionUtil as E;

/**
 * Implements hook_civicrm_config().
 */
function fieldbasedacls_civicrm_config(&$config) {
  _fieldbasedacls_civix_civicrm_config($config);
}

/**
 * Implements hook_civicrm_install().
 */
function fieldbasedacls_civicrm_install() {
  return _fieldbasedacls_civix_civicrm_install();
}

/**
 * Implements hook_civicrm_enable().
 */
function fieldbasedacls_civicrm_enable() {
  return _fieldbasedacls_civix_civicrm_enable();
}

/**
 * Implements hook_civicrm_permission().
 */
function fieldbasedacls_civicrm_permission(&$permissions) {
  $permissions = $permissions + [
    'civicrm administer field-based permissions' => ['label' => E::ts('CiviCRM Field Based Permissions: Administer field based permissions')],
  ];
}

/**
 * Implements hook_civicrm_tabset().
 */
function fieldbasedacls_civicrm_tabset($tabsetName, &$tabs, $context) {

  if (CRM_Core_Permission::check('civicrm administer field-based permissions')) {
    return;
  }

  $permissions_tab = Civi::settings()->get('fieldbasedacls_civicrm_tabs') ?? 0;
  if ($tabsetName == 'civicrm/contact/view') {
    foreach ($tabs as $id => $tab) {
      if ($tab['id'] == 'custom_' . (Civi::settings()->get('fieldbasedacls_civicrm_tabs') ??  '')) {
        unset($tabs[$id]);
      }
    }
  }
}

/**
 * Implements hook_civicrm_aclWhereClause().
 *
 * restrict users to contacts they are granted access to via "Regional Access" custom data tab
 */
function fieldbasedacls_civicrm_aclWhereClause($type, &$tables, &$whereTables, &$contactID, &$where, $acl = 0) {
  if (!$contactID || !fieldbasedacls_acls_enabled()) {
    return;
  }

  $permissionGrantCustomGroup = Civi::settings()->get('fieldbasedacls_acl_grant_table');
  // get table identity of data on custom data tab from which permissions are taken
  $permissionTable = fieldbasedacls_get_grant_table();
  $regionTable = fieldbasedacls_get_to_table();
  $perms = fieldbasedacls_construct_permissions_array($permissionGrantCustomGroup);

  // get all the values from the permission table for this contact
  $keys = [];
  foreach ($perms as $p) {
    $keys[] = $p['perm_field'];
  }
  $keys = implode(', ', $keys);
  $sql = "
    SELECT $keys
    FROM   $permissionTable
    WHERE  entity_id = %1
  ";

  $dao = CRM_Core_DAO::executeQuery($sql, [1 => [$contactID, 'Integer']]);
  if (!$dao->fetch()) {
    return;
  }
  $clauses = [];

  foreach ($perms as $perm) {
    $perm_field = $perm['perm_field'];
    if (empty($dao->{$perm_field})) {
      continue;
    }
    else {
      $permValues = fieldbasedacls_convert_perms_to_array($dao->{$perm_field});
      $fieldType = civicrm_api3('custom_field', 'getvalue', [
        'return' => 'html_type',
        'column_name' => $perm['to_field'],
      ]);

      switch ($fieldType) {
        case 'Select':
          foreach ($permValues as $permission) {
            $serialize = civicrm_api3('custom_field', 'getvalue', [
              'return' => 'serialize',
              'column_name' => $perm['to_field'],
            ]);
            if ($serialize) {
              $clauses[] = " {$regionTable}.{$perm['to_field']}
                LIKE '%" . CRM_Core_DAO::VALUE_SEPARATOR . "$permission" . CRM_Core_DAO::VALUE_SEPARATOR . "%' ";
            }
            else {
              $clauses[] = " {$regionTable}.{$perm['to_field']} = '$permission'";
            }
          }
          break;

        case 'Checkbox':
          foreach ($permValues as $permission) {
            $clauses[] = " {$regionTable}.{$perm['to_field']}
              LIKE '%" . CRM_Core_DAO::VALUE_SEPARATOR . "$permission" . CRM_Core_DAO::VALUE_SEPARATOR . "%' ";
          }
          break;

        default:
          foreach ($permValues as $permission) {
            $clauses[] = " {$regionTable}.{$perm['to_field']} = '$permission'";
          }
      }
    }
  }

  if (empty($clauses)) {
    return;
  }
  $tables[$regionTable] = $whereTables[$regionTable] = "LEFT JOIN {$regionTable} ON contact_a.id = {$regionTable}.entity_id";

  if (strlen(trim($where)) != 0) {
    $where .= ' AND ';
  }
  $where .= '(' . implode(' OR ', $clauses) . ')';
}

/**
 *
 * @param unknown $customgroup
 * @param unknown $type
 * @return unknown|boolean
 */
function fieldbasedacls_get_permissions_field($customgroup, $type) {
  // get CiviCRM Custom Data Groups
  $query = "SELECT id, label, column_name FROM civicrm_custom_field WHERE custom_group_id = '$customgroup' AND label LIKE '%$type%'";
  $dao = CRM_Core_DAO::executeQuery($query);
  // do an or of all the where clauses u see
  $custom_fields = [];
  while ($dao->fetch()) {
    $custom_fields = $dao->column_name;
  }
  if (!empty($custom_fields)) {
    return $custom_fields;
  }
  return FALSE;
}

function fieldbasedacls_get_grant_table() {
  $customTableID = Civi::settings()->get('fieldbasedacls_acl_grant_table');
  return civicrm_api3('custom_group', 'getvalue', array('return' => 'table_name', 'id' => $customTableID));
}

function fieldbasedacls_get_to_table() {
  $customTableID = Civi::settings()->get('fieldbasedacls_acl_to_table');
  return civicrm_api3('custom_group', 'getvalue', array('return' => 'table_name', 'id' => $customTableID));
}

/**
 * Construct array of fields to be used for permissioning based on permissions array
 */
function fieldbasedacls_construct_permissions_array($permissionGrantGroup) {
  $mappings = Civi::settings()->get('fieldbasedacls_acl_field_label_map');
  $perms = [];
  foreach ($mappings as $grant => $to) {
    $grantField = fieldbasedacls_get_permissions_field($permissionGrantGroup, $grant);
    if (!empty($grantField)) {
      $perms[] = [
        'perm_field' => $grantField,
        'to_field' => $to,
      ];
    }
  }
  return $perms;
}

/**
 * Permission value might be a single or mulitple field with the formatting that goes with
 * that - convert to array
 *
 * @param string $permissionString
 */
function fieldbasedacls_convert_perms_to_array($permissionString) {
  if (strpos($permissionString, CRM_Core_DAO::VALUE_SEPARATOR) !== FALSE) {
    $value = addslashes(substr($permissionString, 1, -1));
    $permValues = explode(CRM_Core_DAO::VALUE_SEPARATOR, $value);
  }
  else {
    $permValues = array($permissionString);
  }
  return $permValues;
}

/**
 * Check if field based acls are enabled for this domain & whether these ACLS should be bypassed
 * aclWhere won't be called if the person has 'view all contacts' but we should also respect 'view all contacts in domain'
 * @return void|boolean
 */
function fieldbasedacls_acls_enabled() {
  try {
    if (CRM_Core_Permission::check([['view all contacts in domain', 'edit all contacts in domain']])
      || !Civi::settings()->get('fieldbasedacls_acl_is_enabled')) {
      return FALSE;
    }
  }
  catch (Exception $e) {
    return FALSE;
  }
  return TRUE;
}
