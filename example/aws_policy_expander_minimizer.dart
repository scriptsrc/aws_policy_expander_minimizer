// Copyright (c) 2015, <your name>. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

library aws_policy_expander_minimizer.example;

import 'package:aws_policy_expander_minimizer/aws_policy_expander_minimizer.dart';

main() {
  var policy = {
    "Statement": [{
        "Action": ["swf:res*"],
        "Resource": "*",
        "Effect": "Allow"
      }]
  };

  var expander = new Expander();
  Map expanded = expander.expandPolicy(policy);

  /// expanded =
  /// {
  ///   "Statement": [{
  ///     "Action": [
  ///       "swf:respondactivitytaskcanceled",
  ///       "swf:respondactivitytaskcompleted",
  ///       "swf:respondactivitytaskfailed",
  ///       "swf:responddecisiontaskcompleted"
  ///     ],
  ///     "Resource": "*",
  ///     "Effect": "Allow"
  ///   }]
  /// }

  var minimizer = new Minimizer();
  Map minimized = minimizer.minimizePolicy(expanded, 0);

  print("Policy:    $policy");
  print("Expanded:  $expanded");
  print("Minimized: $minimized");

  /// minimized =
  /// {
  ///   "Statement": [{
  ///     "Action": ["swf:res*"],
  ///     "Resource": "*",
  ///     "Effect": "Allow"
  ///   }]
  /// };
}