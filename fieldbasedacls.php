<?php

require_once 'fieldbasedacls.civix.php';

/**
 * Implementation of hook_civicrm_config
 */
function fieldbasedacls_civicrm_config(&$config) {
  _fieldbasedacls_civix_civicrm_config($config);
}

/**
 * Implementation of hook_civicrm_xmlMenu
 *
 * @param $files array(string)
 */
function fieldbasedacls_civicrm_xmlMenu(&$files) {
  _fieldbasedacls_civix_civicrm_xmlMenu($files);
}

/**
 * Implementation of hook_civicrm_install
 */
function fieldbasedacls_civicrm_install() {
  return _fieldbasedacls_civix_civicrm_install();
}

/**
 * Implementation of hook_civicrm_uninstall
 */
function fieldbasedacls_civicrm_uninstall() {
  return _fieldbasedacls_civix_civicrm_uninstall();
}

/**
 * Implementation of hook_civicrm_enable
 */
function fieldbasedacls_civicrm_enable() {
  return _fieldbasedacls_civix_civicrm_enable();
}

/**
 * Implementation of hook_civicrm_disable
 */
function fieldbasedacls_civicrm_disable() {
  return _fieldbasedacls_civix_civicrm_disable();
}

/**
 * Implementation of hook_civicrm_upgrade
 *
 * @param $op string, the type of operation being performed; 'check' or 'enqueue'
 * @param $queue CRM_Queue_Queue, (for 'enqueue') the modifiable list of pending up upgrade tasks
 *
 * @return mixed  based on op. for 'check', returns array(boolean) (TRUE if upgrades are pending)
 *                for 'enqueue', returns void
 */
function fieldbasedacls_civicrm_upgrade($op, CRM_Queue_Queue $queue = NULL) {
  return _fieldbasedacls_civix_civicrm_upgrade($op, $queue);
}

/**
 * Implementation of hook_civicrm_managed
 *
 * Generate a list of entities to create/deactivate/delete when this module
 * is installed, disabled, uninstalled.
 */
function fieldbasedacls_civicrm_managed(&$entities) {
  return _fieldbasedacls_civix_civicrm_managed($entities);
}

/**
 *
 * @param array $permissions
 */
function fieldbasedacls_civicrm_permissions(&$permissions){
 $prefix = ts('CiviCRM Field Based Permissions') . ': ';
 $permissions = $permissions + array(
   'civicrm administer field-based permissions' => $prefix . ts('Administer field based permissions'),
 );
}


function fieldbasedacls_civicrm_tabs(&$tabs, $contactID) {

 if (user_access('administer geo-based permissions')) {
  return;
 }

 $permissions_tab = variable_get('fieldbasedacls_civicrm_tabs', 0);
 foreach ($tabs as $id => $tab) {

  if ($tab['id'] == 'custom_' . variable_get('fieldbasedacls_civicrm_tabs', '')) {
   unset($tabs[$id]);

  }
 }
}

/**
 * Implement CiviCRM's hook_civicrm_aclWhereClause
 *
 * restrict users to contacts they are granted access to via "Regional Access" custom data tab
 *
 *
 */
function fieldbasedacls_civicrm_aclWhereClause($type, &$tables, &$whereTables, &$contactID, &$where, $acl = 0) {
  if (!$contactID || !fieldbasedacls_acls_enabled()) {
   return;
  }

  $permissionGrantCustomGroup = civicrm_api3('setting', 'getvalue', array('name' => 'fieldbasedacls_acl_grant_table', 'group' => 'fieldbasedacls'));
  // get table identity of data on custom data tab from which permissions are taken
  $permissionTable = fieldbasedacls_get_grant_table();
  $regionTable = fieldbasedacls_get_to_table();
  $perms = fieldbasedacls_construct_permissions_array ($permissionGrantCustomGroup);

  // get all the values from the permission table for this contact
  foreach ( $perms as $p ) {
    $keys [] = $p ['perm_field'];
  }
  $keys = implode ( ', ', $keys );
  $sql = "
    SELECT $keys
    FROM   $permissionTable
    WHERE  entity_id = %1
  ";

  $dao = CRM_Core_DAO::executeQuery($sql, array(1 => array($contactID, 'Integer')));
  if (! $dao->fetch ()) {
    return;
  }
  $clauses = array ();

  foreach ( $perms as $perm ) {
    if (empty ( $dao->$perm ['perm_field'] )) {
      continue;
    } else {
      $permValues = fieldbasedacls_convert_perms_to_array ($dao->$perm ['perm_field']);
      $fieldType = civicrm_api3('custom_field', 'getvalue', array (
        'return' => 'html_type',
        'column_name' => $perm['to_field']
      ));

     switch ($fieldType) {
       case 'Select' :
         foreach ( $permValues as $permission ) {
           $clauses [] = " {$regionTable}.{$perm['to_field']} = '$permission'";
         }
         break;

       case 'AdvMulti-Select' :
       case 'Multi-Select' :
       case 'Checkbox' :
         foreach ( $permValues as $permission ) {
           $clauses [] = " {$regionTable}.{$perm['to_field']}
           LIKE '%" . CRM_Core_DAO::VALUE_SEPARATOR . "$permission" . CRM_Core_DAO::VALUE_SEPARATOR . "%' ";
         }
         break;
       default :
         foreach ( $permValues as $permission ) {
           $clauses [] = " {$regionTable}.{$perm[to_field]} = '$permission'";
         }
      }
    }
 }

  if (empty ( $clauses )) {
    return;
  }
  $tables [$regionTable] = $whereTables [$regionTable] = "LEFT JOIN {$regionTable} ON contact_a.id = {$regionTable}.entity_id";

  if (strlen ( trim ( $where ) ) != 0) {
    $where .= ' AND ';
  }
  $where .= '(' . implode ( ' OR ', $clauses ) . ')';
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
  $dao = CRM_Core_DAO::executeQuery($query, CRM_Core_DAO::$_nullArray);
  // do an or of all the where clauses u see
  $custom_fields = array();
  while ($dao->fetch()) {
    $custom_fields = $dao->column_name;
  }
  if (! empty($custom_fields)) {
    return $custom_fields;
  }
  return false;
}

function fieldbasedacls_get_grant_table() {
  $customTableID = civicrm_api3('setting', 'getvalue', array('name' => 'fieldbasedacls_acl_grant_table', 'group' => 'fieldbasedacls'));
  return civicrm_api3('custom_group', 'getvalue', array('return' => 'table_name', 'id' => $customTableID));
}

function fieldbasedacls_get_to_table() {
  $customTableID = civicrm_api3('setting', 'getvalue', array('name' => 'fieldbasedacls_acl_to_table', 'group' => 'fieldbasedacls'));
  return civicrm_api3('custom_group', 'getvalue', array('return' => 'table_name', 'id' => $customTableID));
}
/*
* Construct array of fields to be used for permissioning based on permissions array
  */
function fieldbasedacls_construct_permissions_array($permissionGrantGroup) {
  $mappings = civicrm_api3('setting', 'getvalue', array('name' => 'fieldbasedacls_acl_field_label_map', 'group' => 'fieldbasedacls'));
  $perms = array();
  foreach ($mappings as $grant => $to) {
    $grantField = fieldbasedacls_get_permissions_field($permissionGrantGroup, $grant);
    if(!empty($grantField)) {
      $perms[] = array(
        'perm_field' => $grantField,
        'to_field' => $to,
      );
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
function fieldbasedacls_convert_perms_to_array($permissionString){
  if (strpos($permissionString, CRM_Core_DAO::VALUE_SEPARATOR) !== false) {
    $value = addslashes(substr($permissionString, 1, - 1));
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
    if(user_access('view all contacts in domain')
      || user_access('edit all contacts in domain')
      || !civicrm_api3('setting', 'getvalue', array('name' => 'fieldbasedacls_acl_is_enabled', 'group' => 'fieldbasedacls'))) {
        return FALSE;
    }
  }
  catch(Exception $e) {
    return FALSE;
  }
  return TRUE;
}
