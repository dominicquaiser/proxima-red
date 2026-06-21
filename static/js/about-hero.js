/**
 * About-page hero: a sun that eases horizontally across the hero as the user
 * scrolls. Scroll/resize set a target; a rAF loop glides toward it so discrete
 * wheel steps render smoothly. Only `left` is written - `transform` belongs to
 * the CSS entry animation. No-ops without the markup or with reduced motion.
 */
(function () {
  "use strict";

  const EASE = 0.08; // fraction of remaining distance closed per frame
  const EXIT_OVERSHOOT = 0.25; // extra travel past the edge, as a fraction of sun width
  const SNAP_THRESHOLD = 0.3; // px: snap onto target and stop easing
  const REST_THRESHOLD = 0.1; // px: stop scheduling frames
  const HOME_THRESHOLD = 0.5; // px: below this, clear `left` and let CSS rest the sun

  const hero = document.querySelector(".about-hero");
  const sun = document.querySelector(".about-hero__sun");
  if (!hero || !sun) return;
  if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) return;

  let currentX = 0;
  let rafId = null;

  const getTargetX = () => {
    const scrollY = window.scrollY || window.pageYOffset;
    if (scrollY <= 0) return 0;
    const scrollProgress = Math.min(1, scrollY / hero.offsetHeight);
    return scrollProgress * (hero.offsetWidth + sun.offsetWidth * EXIT_OVERSHOOT);
  };

  const frame = () => {
    rafId = null;
    const target = getTargetX();
    currentX += (target - currentX) * EASE;
    if (Math.abs(target - currentX) < SNAP_THRESHOLD) currentX = target;

    if (currentX < HOME_THRESHOLD) {
      sun.style.left = "";
    } else {
      sun.style.left = currentX + "px";
    }

    if (Math.abs(target - currentX) > REST_THRESHOLD) {
      rafId = requestAnimationFrame(frame);
    }
  };

  const onScroll = () => {
    if (!rafId) rafId = requestAnimationFrame(frame);
  };

  window.addEventListener("scroll", onScroll, { passive: true });
  window.addEventListener("resize", onScroll, { passive: true });
})();
