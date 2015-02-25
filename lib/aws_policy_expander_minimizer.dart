// Copyright (c) 2015, Patrick Kelley <pkelley@netflix.com @monkeysecurity. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

/// The aws_policy_expander_minimizer library.
///
///
library aws_policy_expander_minimizer;


export 'src/aws_policy_expander_minimizer_base.dart';

// Extracted to a separate class so they can be tested
// without being exposed as usable methods in the
// Expander/Minimizer class.
// http://stackoverflow.com/questions/19677724/dart-unit-testing-private-methods
export 'src/aws_policy_expander_minimizer_private.dart';
