// Copyright (c) 2015, Patrick Kelley <pkelley@netflix.com @monkeysecurity. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

library aws_policy_expander_minimizer.base;

import "aws_policy_expander_minimizer_private.dart";
import 'dart:convert';
// dart:convert is required for jsonDecode(jsonEncode(..))
// This is the only reasonable way I've found to do a deep copy in dart.
// I tried to use `new Map.from(input_policies);`, but found that this will
// creates a copy that still references subojects from the original.
//
// See: http://stackoverflow.com/questions/13107906/how-can-i-clone-an-object-deep-copy-in-dart
// See: http://stackoverflow.com/questions/21744480/clone-a-list-map-or-set-in-dart

List<String> AWS_POLICY_HEADERS = [
  'rolepolicies',
  'grouppolicies',
  'userpolicies',
  'policy'
];

class Expander {
  PrivateExpander pex;

  expandPolicies(Map input_policies) {
    Map policies = jsonDecode(jsonEncode(input_policies)); // Deep Copy
    for (var header in AWS_POLICY_HEADERS) {
      if (policies.keys.contains(header)) {
        if (header == 'policy') {
          policies[header] = expandPolicy(policies[header]);
        } else {
          for (var policy in policies[header].keys) {
            policies[header][policy] = expandPolicy(policies[header][policy]);
          }
        }
        return policies;
      }
    }
    return expandPolicy(policies);
  }

  expandPolicy(var input_policy) {
    Map policy = jsonDecode(jsonEncode(input_policy)); // Deep Copy
    for (var statement in policy['Statement']) {
      List<dynamic> expanded_actions = [];
      if (statement.containsKey('Action')) {
        expanded_actions = pex.expandWildcardAction(statement['Action']);
      } else if (statement.containsKey('NotAction')) {
        expanded_actions = pex.expandWildcardNotAction(statement['NotAction']);
        statement.remove('NotAction');
      }
      expanded_actions = (new Set<dynamic>.from(expanded_actions)).toList();
      expanded_actions.sort();
      statement['Action'] = expanded_actions;
    }
    return policy;
  }

  Expander() {
    pex = new PrivateExpander();
    pex.setupMasterPermissions();
  }
}

class Minimizer {
  PrivateMinimizer pmi;

  minimizePolicies(Map input_policies, int minChars) {
    Map policies = jsonDecode(jsonEncode(input_policies)); // Deep Copy
    for (var header in AWS_POLICY_HEADERS) {
      if (policies.keys.contains(header)) {
        if (header == 'policy') {
          policies[header] = minimizePolicy(policies[header], minChars);
        } else {
          for (var policy in policies[header].keys) {
            policies[header][policy] =
                minimizePolicy(policies[header][policy], minChars);
          }
        }
        return policies;
      }
    }
    return minimizePolicy(policies, minChars);
  }

  minimizePolicy(Map input_policy, int minChars) {
    Map policy = jsonDecode(jsonEncode(input_policy)); // Deep Copy
    for (var statement in policy['Statement']) {
      var minimized_actions = pmi.minimizeStatementActions(statement, minChars);
      statement['Action'] = minimized_actions;
    }
    return policy;
  }

  Minimizer() {
    pmi = new PrivateMinimizer();
    pmi.setupMasterPermissions();
  }
}
