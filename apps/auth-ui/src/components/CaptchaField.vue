<script setup lang="ts">
/**
 * The tenant's CAPTCHA widget (§6.1).
 *
 * Both providers offer an explicit-render API, so the widget lives exactly where the form puts it
 * instead of injecting itself at load time. The token is handed up on success and dropped when the
 * provider expires or errors it; a rejected submit calls `reset()` because tokens are single-use.
 */
import { onBeforeUnmount, onMounted, ref } from "vue";

const props = defineProps<{
  provider: "turnstile" | "recaptcha";
  siteKey: string;
}>();

const emit = defineEmits<{ "update:token": [token: string | null] }>();

interface Turnstile {
  render: (element: HTMLElement, options: Record<string, unknown>) => string;
  reset: (id: string) => void;
}

interface Recaptcha {
  render: (element: HTMLElement, options: Record<string, unknown>) => number;
  reset: (id: number) => void;
}

interface CaptchaWindow {
  turnstile?: Turnstile;
  grecaptcha?: Recaptcha;
}

const SCRIPT_SOURCES: Record<"turnstile" | "recaptcha", string> = {
  turnstile: "https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit",
  recaptcha: "https://www.google.com/recaptcha/api.js?render=explicit",
};

const container = ref<HTMLDivElement | null>(null);
let widgetId: string | number | null = null;

function loadScript(src: string): Promise<void> {
  const existing = document.querySelector<HTMLScriptElement>(`script[src="${src}"]`);
  if (existing) {
    if (existing.dataset.loaded === "true") return Promise.resolve();
    return new Promise((resolve, reject) => {
      existing.addEventListener("load", () => resolve(), { once: true });
      existing.addEventListener("error", () => reject(new Error("the CAPTCHA script failed to load")), {
        once: true,
      });
    });
  }
  return new Promise((resolve, reject) => {
    const script = document.createElement("script");
    script.src = src;
    script.async = true;
    script.defer = true;
    script.addEventListener(
      "load",
      () => {
        script.dataset.loaded = "true";
        resolve();
      },
      { once: true },
    );
    script.addEventListener("error", () => reject(new Error("the CAPTCHA script failed to load")), {
      once: true,
    });
    document.head.appendChild(script);
  });
}

function installed(): CaptchaWindow {
  return window as unknown as CaptchaWindow;
}

const options = {
  sitekey: props.siteKey,
  callback: (token: string) => emit("update:token", token),
  "expired-callback": () => emit("update:token", null),
  "error-callback": () => emit("update:token", null),
};

onMounted(async () => {
  try {
    await loadScript(SCRIPT_SOURCES[props.provider]);
    if (!container.value) return;
    const api = installed();
    if (props.provider === "turnstile" && api.turnstile) {
      widgetId = api.turnstile.render(container.value, options);
    } else if (props.provider === "recaptcha" && api.grecaptcha) {
      widgetId = api.grecaptcha.render(container.value, options);
    } else {
      emit("update:token", null);
    }
  } catch {
    emit("update:token", null);
  }
});

onBeforeUnmount(() => {
  widgetId = null;
});

function reset(): void {
  emit("update:token", null);
  if (widgetId === null) return;
  if (props.provider === "turnstile") {
    installed().turnstile?.reset(String(widgetId));
  } else {
    installed().grecaptcha?.reset(Number(widgetId));
  }
}

defineExpose({ reset });
</script>

<template>
  <div ref="container" class="flex justify-center" />
</template>
