# aws\_policy\_expander_minimizer

A library for expanding and minimizing AWS policies.

### Expander

The expander works by replacing wildcards with all the matching AWS actions. 

    'iam:get*'

becomes

    'iam:getaccountpasswordpolicy',
    'iam:getaccountsummary',
    'iam:getcredentialreport',
    'iam:getgroup',
    'iam:getgrouppolicy',
    'iam:getinstanceprofile',
    'iam:getloginprofile',
    'iam:getrole',
    'iam:getrolepolicy',
    'iam:getsamlprovider',
    'iam:getservercertificate',
    'iam:getuser',
    'iam:getuserpolicy'

By enumerating all permissions that are allowed by a wildcard, you can better audit your security policies.

### Minimizer

#### Explanation & Gripe :)

The author of this module believes that using wildcards in security policies is an inherently bad thing.  They can obscure the actual permissions being granted in a policy.  Additionally, if AWS rolls out new permissions, these new permissions may be automatically allowed by the wildcards in your existing policies.

However, due to the severe size restrictions on AWS policies (2k for IAM user, 10k for IAM role, whitespace excluded), it is impossible to enumerate all permissions and remain under the size limit.  One approach is to use the NotAction AWS policy statement, listing all permissions that are to be denied and allowing everything else.  This "NotAction" approach is called blacklisting and has time and again proven to be inferior to whitelisting.

Ideally, policies should be very small, simple, and straight forward.  Most policies should be very limited.  This is the best we can strive for.  For situations where this is not possible, this minimizer can be used to shrink your desired policy so that it fits within the AWS limits.


#### Minimizer Description 

The minimizer takes a policy and reduces its size, so you can squeeze more policy and remain under the AWS limits.  It combines multiple actions into a single wildcard action where possible, and reduces the number of characters in these permissions as well.

    "swf:respondactivitytaskcanceled",
    "swf:respondactivitytaskcompleted",
    "swf:respondactivitytaskfailed",
    "swf:responddecisiontaskcompleted"

becomes

    "swf:res*"

##### minChars

The minimizer also takes a minChars parameter that can be used to force the minimizer to keep more characters in the permissions so they are more readable.  The previous example, but with minChars set to 7, produces the following output:

    "swf:respond*"

## Usage

A simple usage example:

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

## Features and bugs

- It currently only works on the Action section of a statement, leaving the rest of the policy the way it was passed in.
- The minimizer currently only works for policies where the "Effect" is set to "Allow".  A "Deny" statement will throw an exception.  It should be pretty easy to adapt to Deny statements.  The expander is not affected by the "Effect".
- This package must be updated whenever AWS releases new permissions.  It is imperative that master_permissions.dart contain all AWS permissions so the minimization process does not allow unwanted permissions in its output.

Please file feature requests and bugs at the [issue tracker][tracker].

[tracker]: http://example.com/issues/replaceme