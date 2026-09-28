package org.satochip.applet;

import org.junit.jupiter.api.extension.ExtendWith;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Marks a test as requiring one or more optional applet capabilities. Tests whose requirements are
 * not met on the current target are skipped with a reason rather than failed.
 *
 * <p>Recognised values are the feature-policy names reported by GET_STATUS ("schnorr", "nostr",
 * "liquid", "musig2", "random") plus the synthetic capability "rsaMult", which is probed
 * behaviourally because the RSA multiplication trick is unavailable on some cards and on an
 * unpatched simulator.
 *
 * @see FeaturePolicyCondition
 */
@Target({ ElementType.TYPE, ElementType.METHOD })
@Retention(RetentionPolicy.RUNTIME)
@ExtendWith(FeaturePolicyCondition.class)
public @interface FeaturePolicies {
  String[] value();
}
