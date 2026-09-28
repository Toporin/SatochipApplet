package org.satochip.applet;

import org.junit.jupiter.api.extension.ConditionEvaluationResult;
import org.junit.jupiter.api.extension.ExecutionCondition;
import org.junit.jupiter.api.extension.ExtensionContext;

import java.lang.reflect.AnnotatedElement;
import java.util.HashSet;
import java.util.Optional;

import static org.junit.jupiter.api.extension.ConditionEvaluationResult.disabled;
import static org.junit.jupiter.api.extension.ConditionEvaluationResult.enabled;
import static org.junit.platform.commons.util.AnnotationUtils.findAnnotation;

/**
 * Implements {@link FeaturePolicies} by comparing the annotation's values against the set of
 * capabilities detected on the current target in {@code @BeforeAll}.
 */
public class FeaturePolicyCondition implements ExecutionCondition {
  private static final ConditionEvaluationResult ENABLED_BY_DEFAULT =
      enabled("@FeaturePolicies is not present");
  private static final ConditionEvaluationResult ENABLED =
      enabled("All required capabilities are available");

  /** Populated by SatochipTest.detectCapabilities(). */
  static HashSet<String> availableCapabilities = new HashSet<>();

  @Override
  public ConditionEvaluationResult evaluateExecutionCondition(ExtensionContext context) {
    Optional<AnnotatedElement> element = context.getElement();
    Optional<FeaturePolicies> annotation = findAnnotation(element, FeaturePolicies.class);

    if (!annotation.isPresent()) {
      return ENABLED_BY_DEFAULT;
    }

    for (String capability : annotation.get().value()) {
      if (!availableCapabilities.contains(capability)) {
        return disabled("The '" + capability + "' capability is not available on this target");
      }
    }

    return ENABLED;
  }
}
