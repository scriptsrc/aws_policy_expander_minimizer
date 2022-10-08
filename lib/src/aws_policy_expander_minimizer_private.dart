// Copyright (c) 2015, Patrick Kelley <pkelley@netflix.com @monkeysecurity. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

library aws_policy_expander_minimizer.private;

import "master_permissions.dart" show AWS_PERMISSIONS;

class PrivateExpander {
  Set<dynamic> master_permissions = new Set<dynamic>();

  setupMasterPermissions() {
    for (var technology_name in AWS_PERMISSIONS.keys) {
      var technology_prefix = AWS_PERMISSIONS[technology_name]["StringPrefix"];
      for (var action in AWS_PERMISSIONS[technology_name]["Actions"]) {
        master_permissions.add("$technology_prefix:${action.toLowerCase()}");
      }
    }
  }

  List<dynamic> expandWildcardAction(var action) {
    if (action is String) {
      if (action.contains('*')) {
        String pre_wildcard = action.split('*')[0];
        List<dynamic> expanded = [];
        master_permissions.forEach((master_action) {
          if (master_action.startsWith(pre_wildcard.toLowerCase())) {
            expanded.add(master_action.toLowerCase());
          }
        });
        return expanded;
      }
      return [action.toLowerCase()];
    } else if (action is List) {
      List<dynamic> expanded = [];
      for (var item in action) {
        expanded.addAll(expandWildcardAction(item));
      }
      return expanded;
    } else {
      throw new InvalidInputException(
          'expandWildcardAction requires a string or list of strings');
    }
  }

  List<dynamic> expandWildcardNotAction(var not_action) {
    Set<dynamic> action_set = new Set<dynamic>.from(master_permissions);
    if (not_action is String) {
      return action_set
          .difference(new Set<dynamic>.from(expandWildcardAction(not_action)))
          .toList();
    } else if (not_action is List) {
      for (var item in not_action) {
        action_set = action_set
            .difference(new Set<dynamic>.from(expandWildcardAction(item)));
      }
      return action_set.toList();
    } else {
      throw new InvalidInputException(
          'expandWildcardNotAction requires a string or list of strings');
    }
  }
}

/// The minimizer extends the expander because
/// all statements must be expanded before they
/// are minimized.
class PrivateMinimizer extends PrivateExpander {
  List<dynamic> getPrefixesForAction(String action) {
    List<dynamic> retval = [];

    String technology, permission;
    List<String> parts = action.split(':');
    technology = parts[0];
    permission = parts[1];

    retval.add("$technology:");
    var phrase = "";

    for (var char in permission.split('')) {
      var newPhrase = "$phrase$char";
      retval.add("$technology:$newPhrase");
      phrase = newPhrase;
    }

    return retval;
  }

  getDesiredActionsFromStatement(Map<String, Object> statement) {
    Set desired_actions = new Set();
    var actions = expandWildcardAction(statement['Action']);

    for (var action in actions) {
      if (!master_permissions.contains(action)) {
        throw new UnknownPermissionException("Permission <$action> not known.");
      }
      desired_actions.add(action);
    }

    return desired_actions;
  }

  Set<dynamic> getDeniedPrefixesFromDesired(Set<dynamic> desired_actions) {
    Set<dynamic> denied_actions =
        master_permissions.difference(desired_actions);
    Set<dynamic> denied_prefixes = new Set<dynamic>();
    for (var denied_action in denied_actions) {
      for (var denied_prefix in getPrefixesForAction(denied_action)) {
        denied_prefixes.add(denied_prefix);
      }
    }
    return denied_prefixes;
  }

  bool checkPermissionLength(String permission, int minChars) {
    if (permission.length > 0) {
      if (permission.length < minChars) {
        //print("Skipping prefix $permission because length of ${permission.length}");
        return true;
      }
    }
    return false;
  }

  List<dynamic> minimizeStatementActions(Map statement, int minChars) {
    Set<dynamic> minimized_actions = new Set<dynamic>();

    if (statement['Effect'] != 'Allow')
      throw new StatementNotMinifiableException(
          'Minification does not currently work on Deny statements.');

    Set<dynamic> desired_actions = getDesiredActionsFromStatement(statement);
    Set<dynamic> denied_prefixes =
        getDeniedPrefixesFromDesired(desired_actions);

    for (var action in desired_actions) {
      if (denied_prefixes.contains(action)) {
        minimized_actions.add(action);
        continue;
      }

      bool found_prefix = false;

      var prefixes = getPrefixesForAction(action);

      for (var prefix in prefixes) {
        var permission = prefix.split(':')[1];
        if (checkPermissionLength(permission, minChars)) {
          continue;
        }

        if (!denied_prefixes.contains(prefix)) {
          if (!desired_actions.contains(prefix)) {
            prefix = "$prefix*";
          }
          minimized_actions.add(prefix);
          found_prefix = true;
          break;
        }
      }

      if (!found_prefix) {
        minimized_actions.add(prefixes.last);
      }
    }

    List<dynamic> minimized_actions_list = minimized_actions.toList();
    minimized_actions_list.sort();
    return minimized_actions_list;
  }
}

class InvalidInputException implements Exception {
  String cause;
  InvalidInputException(this.cause);
}

class StatementNotMinifiableException implements Exception {
  String cause;
  StatementNotMinifiableException(this.cause);
}

class UnknownPermissionException implements Exception {
  String cause;
  UnknownPermissionException(this.cause);
}
