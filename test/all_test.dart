// Copyright (c) 2015, Patrick Kelley <pkelley@netflix.com> @monkeysecurity. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

library aws_policy_expander_minimizer.test;

import 'package:unittest/unittest.dart';
import 'package:aws_policy_expander_minimizer/aws_policy_expander_minimizer.dart';

main() {

  ///
  /// Minimizer Private
  ///
  group('Minimizer Private Method Tests', () {
    PrivateMinimizer pmi;

    setUp(() {
      pmi = new PrivateMinimizer();
      pmi.setupMasterPermissions();
    });

    test('prefixesForAction', () {
      var prefixes = pmi.getPrefixesForAction("iam:cat");
      expect(prefixes, ["iam:", "iam:c", "iam:ca", "iam:cat"]);
    });

    test('getDesiredActionsFromStatement', () {
      var statement = {
          "Action": [
              "swf:respond*"
          ],
          "Resource": "*",
          "Effect": "Allow"
      };
      var desired_actions = pmi.getDesiredActionsFromStatement(statement);
      expect(desired_actions,
       new Set.from([
         "swf:respondactivitytaskcanceled",
         "swf:respondactivitytaskcompleted",
         "swf:respondactivitytaskfailed",
         "swf:responddecisiontaskcompleted"
       ])
      );
    });

    test('getDesiredActionsFromStatement no wildcard', () {
      var statement = {
          "Action": [
              "swf:respondactivitytaskcanceled"
          ],
          "Resource": "*",
          "Effect": "Allow"
      };
      var desired_actions = pmi.getDesiredActionsFromStatement(statement);
      expect(desired_actions,
       new Set.from([
         "swf:respondactivitytaskcanceled",
       ])
      );
    });

    test('getDeniedPrefixesFromDesired', () {
      Set<String> desired_actions = new Set.from([
        "aws-marketplace-management:uploadfiles",
        "aws-marketplace-management:viewmarketing",
        //"aws-marketplace-management:viewreports",
        "aws-marketplace-management:viewsupport"
      ]);
      Set<String> denied_actions = pmi.getDeniedPrefixesFromDesired(desired_actions);
      expect(denied_actions.contains("aws-marketplace-management:viewreports"), true);
      expect(denied_actions.contains("aws-marketplace-management:viewreport"), true);
      expect(denied_actions.contains("aws-marketplace-management:viewrepor"), true);
      expect(denied_actions.contains("aws-marketplace-management:viewrepo"), true);
      expect(denied_actions.contains("aws-marketplace-management:viewrep"), true);
      expect(denied_actions.contains("aws-marketplace-management:viewre"), true);
      expect(denied_actions.contains("aws-marketplace-management:viewr"), true);
      expect(denied_actions.contains("aws-marketplace-management:view"), true);
      expect(denied_actions.contains("aws-marketplace-management:vie"), true);
      expect(denied_actions.contains("aws-marketplace-management:vi"), true);
      expect(denied_actions.contains("aws-marketplace-management:v"), true);
      expect(denied_actions.contains("aws-marketplace-management:"), true);

      expect(denied_actions.contains("aws-marketplace-management:viewsupport"), false);
      expect(denied_actions.contains("trustedadvisor:describechecksummaries"), true);
      expect(denied_actions.contains("trustedadvisor:describe"), true);

    });

    test('check_min_permission_length_false', () {
      expect(pmi.checkPermissionLength('long_permission', 5), false);
    });

    test('check_min_permission_length_true', () {
      expect(pmi.checkPermissionLength('get', 5), true);
    });

    test('minimizeStatementActions', () {
      var statement = {
          "Action": [
              "swf:respondactivitytaskcanceled",
              "swf:respondactivitytaskcompleted",
              "swf:respondactivitytaskfailed",
              "swf:responddecisiontaskcompleted"
          ],
          "Resource": "*",
          "Effect": "Allow"
      };

      List<String> minimized_actions = pmi.minimizeStatementActions(statement, 0);
      expect(minimized_actions, ["swf:res*"]);

    });

    test('minimizeStatementActions minChars', () {
      var statement = {
          "Action": [
              "swf:respondactivitytaskcanceled",
              "swf:respondactivitytaskcompleted",
              "swf:respondactivitytaskfailed",
              "swf:responddecisiontaskcompleted"
          ],
          "Resource": "*",
          "Effect": "Allow"
      };

      List<String> minimized_actions = pmi.minimizeStatementActions(statement, 7);
      expect(minimized_actions, ["swf:respond*"]);

    });

  });

  ///
  /// Minimizer Public
  ///
  group('Minimizer Public Method Tests', () {
      Minimizer minimizer;

      setUp(() {
        minimizer = new Minimizer();
      });

      test('minimize policy with single policy', () {
        var policy = {
          "Statement": [{
            "Action": [
              "swf:respondactivitytaskcanceled",
              "swf:respondactivitytaskcompleted",
              "swf:respondactivitytaskfailed",
              "swf:responddecisiontaskcompleted"
            ],
            "Resource": "*",
            "Effect": "Allow"
          }]
        };
        var minimized = minimizer.minimizePolicy(policy, 0);
        expect(minimized,
          {
            "Statement": [{
              "Action": [
                "swf:res*"
              ],
              "Resource": "*",
              "Effect": "Allow"
            }]
          }
        );
      });

      test('minimize policy without modifying passed in datastructure', () {
        var policy = {
          "Statement": [{
            "Action": [
              "swf:respondactivitytaskcanceled",
              "swf:respondactivitytaskcompleted",
              "swf:respondactivitytaskfailed",
              "swf:responddecisiontaskcompleted"
            ],
            "Resource": "*",
            "Effect": "Allow"
          }]
        };
        var minimized = minimizer.minimizePolicy(policy, 0);
        expect(policy,
          {
            "Statement": [{
              "Action": [
                "swf:respondactivitytaskcanceled",
                "swf:respondactivitytaskcompleted",
                "swf:respondactivitytaskfailed",
                "swf:responddecisiontaskcompleted"
              ],
              "Resource": "*",
              "Effect": "Allow"
            }]
          }
        );
      });

      test('minimize policy with multiple policies', () {
        var policies = {
          "rolepolicies": {
            "PolName1": {
              "Statement": [
                {
                  "Action": [
                    "swf:respondactivitytaskcanceled",
                    "swf:respondactivitytaskcompleted",
                    "swf:respondactivitytaskfailed",
                    "swf:responddecisiontaskcompleted"
                  ],
                  "Resource": "*",
                  "Effect": "Allow"
                }
              ]
            },
            "PolName2": {
              "Statement": [
                {
                  "Action": [
                    "kinesis:getsharditerator",
                    "kinesis:getrecords"
                  ],
                  "Resource": "*",
                  "Effect": "Allow"
                }
              ]
            }
          }
        };
        var minimized = minimizer.minimizePolicies(policies, 3);
        expect(minimized,
          {
            "rolepolicies": {
              "PolName1": {
                "Statement": [
                  {
                    "Action": [
                      "swf:res*"
                    ],
                    "Resource": "*",
                    "Effect": "Allow"
                  }
                ]
              },
              "PolName2": {
                "Statement": [
                  {
                    "Action": [
                      "kinesis:get*"
                    ],
                    "Resource": "*",
                    "Effect": "Allow"
                  }
                 ]
              }
            }
          }
        );
      });

      test('minimize policy with multiple policies without modifying passed in datastructure', () {
        var policies = {
          "rolepolicies": {
            "PolName1": {
              "Statement": [
                {
                  "Action": [
                    "swf:respondactivitytaskcanceled",
                    "swf:respondactivitytaskcompleted",
                    "swf:respondactivitytaskfailed",
                    "swf:responddecisiontaskcompleted"
                  ],
                  "Resource": "*",
                  "Effect": "Allow"
                }
              ]
            },
            "PolName2": {
              "Statement": [
                {
                  "Action": [
                    "kinesis:getsharditerator",
                    "kinesis:getrecords"
                  ],
                  "Resource": "*",
                  "Effect": "Allow"
                }
              ]
            }
          }
        };
        var minimized = minimizer.minimizePolicies(policies, 3);
        expect(policies,
          {
            "rolepolicies": {
              "PolName1": {
                "Statement": [
                  {
                    "Action": [
                      "swf:respondactivitytaskcanceled",
                      "swf:respondactivitytaskcompleted",
                      "swf:respondactivitytaskfailed",
                      "swf:responddecisiontaskcompleted"
                    ],
                    "Resource": "*",
                    "Effect": "Allow"
                  }
                ]
              },
              "PolName2": {
                "Statement": [
                  {
                    "Action": [
                      "kinesis:getsharditerator",
                      "kinesis:getrecords"
                    ],
                    "Resource": "*",
                    "Effect": "Allow"
                  }
                ]
              }
            }
          }
        );
      });
    });


  ///
  /// Expander Private
  ///
  group('Expander Private Method Tests', () {
    PrivateExpander pex;

    setUp(() {
      pex = new PrivateExpander();
      pex.setupMasterPermissions();
    });

    test('expandWildcardAction with autoscaling:*', () {
      var expanded = pex.expandWildcardAction('autoscaling:*');
      expect(expanded, [
        "autoscaling:attachinstances",
        "autoscaling:completelifecycleaction",
        "autoscaling:createautoscalinggroup",
        "autoscaling:createlaunchconfiguration",
        "autoscaling:createorupdatetags",
        "autoscaling:deleteautoscalinggroup",
        "autoscaling:deletelaunchconfiguration",
        "autoscaling:deletelifecyclehook",
        "autoscaling:deletenotificationconfiguration",
        "autoscaling:deletepolicy",
        "autoscaling:deletescheduledaction",
        "autoscaling:deletetags",
        "autoscaling:describeaccountlimits",
        "autoscaling:describeadjustmenttypes",
        "autoscaling:describeautoscalinggroups",
        "autoscaling:describeautoscalinginstances",
        "autoscaling:describeautoscalingnotificationtypes",
        "autoscaling:describelaunchconfigurations",
        "autoscaling:describelifecyclehooktypes",
        "autoscaling:describelifecyclehooks",
        "autoscaling:describemetriccollectiontypes",
        "autoscaling:describenotificationconfigurations",
        "autoscaling:describepolicies",
        "autoscaling:describescalingactivities",
        "autoscaling:describescalingprocesstypes",
        "autoscaling:describescheduledactions",
        "autoscaling:describetags",
        "autoscaling:describeterminationpolicytypes",
        "autoscaling:detachinstances",
        "autoscaling:disablemetricscollection",
        "autoscaling:enablemetricscollection",
        "autoscaling:enterstandby",
        "autoscaling:executepolicy",
        "autoscaling:exitstandby",
        "autoscaling:putlifecyclehook",
        "autoscaling:putnotificationconfiguration",
        "autoscaling:putscalingpolicy",
        "autoscaling:putscheduledupdategroupaction",
        "autoscaling:recordlifecycleactionheartbeat",
        "autoscaling:resumeprocesses",
        "autoscaling:setdesiredcapacity",
        "autoscaling:setinstancehealth",
        "autoscaling:suspendprocesses",
        "autoscaling:terminateinstanceinautoscalinggroup",
        "autoscaling:updateautoscalinggroup"
      ]);
    });

    test('expandWildcardAction with autoscaling:describe*', () {
      var expanded = pex.expandWildcardAction('autoscaling:describe*');
      expect(expanded, [
        "autoscaling:describeaccountlimits",
        "autoscaling:describeadjustmenttypes",
        "autoscaling:describeautoscalinggroups",
        "autoscaling:describeautoscalinginstances",
        "autoscaling:describeautoscalingnotificationtypes",
        "autoscaling:describelaunchconfigurations",
        "autoscaling:describelifecyclehooktypes",
        "autoscaling:describelifecyclehooks",
        "autoscaling:describemetriccollectiontypes",
        "autoscaling:describenotificationconfigurations",
        "autoscaling:describepolicies",
        "autoscaling:describescalingactivities",
        "autoscaling:describescalingprocesstypes",
        "autoscaling:describescheduledactions",
        "autoscaling:describetags",
        "autoscaling:describeterminationpolicytypes",
      ]);
    });
  });

  ///
  /// Expander Public
  ///
  group('Expander Public Method Tests', () {
    Expander expander;

    setUp(() {
      expander = new Expander();
    });

    test('expand policies with single "policy" header', () {
      var policy = {
        "policy": {
          "Version": "2008-10-17",
          "Id": "__default_policy_ID",
          "Statement": [
            {
              "Resource": "arn:aws:sns:eu-west-1:XXXX:blah",
              "Effect": "Allow",
              "Sid": "statementID",
              "Action": [
                "SNS:Publish",
                "SNS:RemovePermission",
                "SNS:SetTopicAttributes",
                "SNS:DeleteTopic",
                "SNS:ListSubscriptionsByTopic",
                "SNS:GetTopicAttributes",
                "SNS:Receive",
                "SNS:AddPermission",
                "SNS:Subscribe"
              ],
              "Principal": {
                "AWS": "*"
              }
            }
          ]
        }
      };
      var expanded = expander.expandPolicies(policy);
      expect(expanded, {
        "policy": {
          "Version": "2008-10-17",
          "Id": "__default_policy_ID",
          "Statement": [{
            "Resource": "arn:aws:sns:eu-west-1:XXXX:blah",
            "Effect": "Allow",
            "Sid": "statementID",
            "Action": [
              'sns:addpermission',
              'sns:deletetopic',
              'sns:gettopicattributes',
              'sns:listsubscriptionsbytopic',
              'sns:publish',
              'sns:receive',
              'sns:removepermission',
              'sns:settopicattributes',
              'sns:subscribe'
            ],
            "Principal": {
              "AWS": "*"
            }
          }]
        }
      });
    });

    test('expand policy with single policy', () {
      var policy = {
        "Statement": [{
            "Action": ["swf:res*"],
            "Resource": "*",
            "Effect": "Allow"
          }]
      };
      var expanded = expander.expandPolicy(policy);
      expect(expanded, {
        "Statement": [{
            "Action": [
              "swf:respondactivitytaskcanceled",
              "swf:respondactivitytaskcompleted",
              "swf:respondactivitytaskfailed",
              "swf:responddecisiontaskcompleted"
            ],
            "Resource": "*",
            "Effect": "Allow"
          }]
      });
    });

    test('expand policy with single policy without modifying input datastructure', () {
      var policy = {
        "Statement": [{
            "Action": ["swf:res*"],
            "Resource": "*",
            "Effect": "Allow"
          }]
      };
      var expanded = expander.expandPolicy(policy);
      expect(policy, {
        "Statement": [{
          "Action": ["swf:res*"],
          "Resource": "*",
          "Effect": "Allow"
        }]
      });
    });

    test('expand policy with multiple policies', () {

      var policies = {
        "rolepolicies": {
          "PolName1": {
            "Statement": [{
                "Action": ["swf:res*"],
                "Resource": "*",
                "Effect": "Allow"
              }]
          },
          "PolName2": {
            "Statement": [{
                "Action": ["kinesis:get*"],
                "Resource": "*",
                "Effect": "Allow"
              }]
          }
        }
      };
      var expanded = expander.expandPolicies(policies);
      expect(expanded,
        {
          "rolepolicies": {
            "PolName1": {
              "Statement": [{
                  "Action": [
                    "swf:respondactivitytaskcanceled",
                    "swf:respondactivitytaskcompleted",
                    "swf:respondactivitytaskfailed",
                    "swf:responddecisiontaskcompleted"
                  ],
                  "Resource": "*",
                  "Effect": "Allow"
                }]
            },
            "PolName2": {
              "Statement": [
                {
                  "Action": [
                    "kinesis:getrecords",
                    "kinesis:getsharditerator"
                  ],
                  "Resource": "*",
                  "Effect": "Allow"
                }
              ]
            }
          }
        }
      );
    });

    test('expand policy with multiple policies without modifying input datastructure', () {

      var policies = {
        "rolepolicies": {
          "PolName1": {
            "Statement": [{
                "Action": ["swf:res*"],
                "Resource": "*",
                "Effect": "Allow"
              }]
          },
          "PolName2": {
            "Statement": [{
                "Action": ["kinesis:get*"],
                "Resource": "*",
                "Effect": "Allow"
              }]
          }
        }
      };
      var expanded = expander.expandPolicies(policies);
      expect(policies,
        {
          "rolepolicies": {
            "PolName1": {
              "Statement": [{
                "Action": ["swf:res*"],
                "Resource": "*",
                "Effect": "Allow"
              }]
            },
            "PolName2": {
              "Statement": [{
                "Action": ["kinesis:get*"],
                "Resource": "*",
                "Effect": "Allow"
              }]
            }
          }
        }
      );
    });

    test('expand policy wildcard with uppercase', () {
      var policy = {
        "Statement": [{
            "Action": ["ec2:Describe*"],
            "Resource": "*",
            "Effect": "Allow"
          }]
      };
      var expanded = expander.expandPolicy(policy);
      expect(expanded, {
        "Statement": [{
            "Action": [
              "ec2:describeaccountattributes",
              "ec2:describeaddresses",
              "ec2:describeavailabilityzones",
              "ec2:describebundletasks",
              "ec2:describeclassiclinkinstances",
              "ec2:describeconversiontasks",
              "ec2:describecustomergateways",
              "ec2:describedhcpoptions",
              "ec2:describeexporttasks",
              "ec2:describeflowlogs",
              "ec2:describeimageattribute",
              "ec2:describeimages",
              "ec2:describeimportimagetasks",
              "ec2:describeimportsnapshottasks",
              "ec2:describeinstanceattribute",
              "ec2:describeinstances",
              "ec2:describeinstancestatus",
              "ec2:describeinternetgateways",
              "ec2:describekeypairs",
              "ec2:describelicenses",
              "ec2:describenetworkacls",
              "ec2:describenetworkinterfaceattribute",
              "ec2:describenetworkinterfaces",
              "ec2:describeplacementgroups",
              "ec2:describeprefixlists",
              "ec2:describeregions",
              "ec2:describereservedinstances",
              "ec2:describereservedinstanceslistings",
              "ec2:describereservedinstancesmodifications",
              "ec2:describereservedinstancesofferings",
              "ec2:describeroutetables",
              "ec2:describesecuritygroups",
              "ec2:describesnapshotattribute",
              "ec2:describesnapshots",
              "ec2:describespotdatafeedsubscription",
              "ec2:describespotfleetinstances",
              "ec2:describespotfleetrequesthistory",
              "ec2:describespotfleetrequests",
              "ec2:describespotinstancerequests",
              "ec2:describespotpricehistory",
              "ec2:describesubnets",
              "ec2:describetags",
              "ec2:describevolumeattribute",
              "ec2:describevolumes",
              "ec2:describevolumestatus",
              "ec2:describevpcattribute",
              "ec2:describevpcclassiclink",
              "ec2:describevpcendpoints",
              "ec2:describevpcendpointservices",
              "ec2:describevpcpeeringconnections",
              "ec2:describevpcs",
              "ec2:describevpnconnections",
              "ec2:describevpngateways"
            ],
            "Resource": "*",
            "Effect": "Allow"
          }]
      });
    });

  });
}
