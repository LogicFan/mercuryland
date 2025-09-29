<script setup lang="ts">
import { onMounted, ref } from "vue";
import axios from "axios";
import { BASE_URL } from "@/composables/utils";

const CLIENT_ID = import.meta.env.VITE_GOOGLE_SSO_CLIENT_ID;
const SCRIPT_ID = "google-identity-services";

const buttonContainer = ref<HTMLDivElement | null>(null);

interface CredentialResponse {
    credential?: string;
    select_by?: string;
    clientId?: string;
}

interface SessionResponse {
    token: string;
    email?: string;
    name?: string;
}

const props = defineProps<{
    clientIp?: string | null;
}>();

const emit = defineEmits<{
    (e: "login-success", payload: SessionResponse): void;
    (e: "login-error", error: unknown): void;
}>();

type GoogleAccounts = {
    id: {
        initialize: (
            config: {
                client_id: string;
                callback: (response: CredentialResponse) => void;
            }
        ) => void;
        renderButton: (element: HTMLElement, options: Record<string, unknown>) => void;
        cancel: () => void;
        prompt: () => void;
    };
};

type GoogleGlobal = {
    accounts: GoogleAccounts;
};

declare global {
    interface Window {
        google?: GoogleGlobal;
    }
}

let googleScriptPromise: Promise<void> | null = null;

function loadGoogleIdentityServices(): Promise<void> {
    if (typeof window === "undefined") {
        return Promise.resolve();
    }

    if (window.google?.accounts?.id) {
        return Promise.resolve();
    }

    if (googleScriptPromise) {
        return googleScriptPromise;
    }

    googleScriptPromise = new Promise((resolve, reject) => {
        let script = document.getElementById(SCRIPT_ID) as HTMLScriptElement | null;

        const handleLoad = () => {
            script?.setAttribute("data-loaded", "true");
            resolve();
        };

        const handleError = () =>
            reject(new Error("Failed to load Google Identity Services script"));

        if (!script) {
            script = document.createElement("script");
            script.id = SCRIPT_ID;
            script.src = "https://accounts.google.com/gsi/client";
            script.async = true;
            script.defer = true;
            script.addEventListener("load", handleLoad, { once: true });
            script.addEventListener("error", handleError, { once: true });
            document.head.appendChild(script);
            return;
        }

        if (script.getAttribute("data-loaded") === "true") {
            resolve();
            return;
        }

        script.addEventListener("load", handleLoad, { once: true });
        script.addEventListener("error", handleError, { once: true });
    });

    return googleScriptPromise;
}

async function handleCredentialResponse(response: CredentialResponse) {
    if (!response.credential) {
        emit("login-error", new Error("Missing Google credential"));
        return;
    }

    try {
        const { data } = await axios.post<SessionResponse>(
            `${BASE_URL}/api/auth/google`,
            {
                credential: response.credential,
                ip: props.clientIp ?? undefined,
            }
        );
        emit("login-success", data);
    } catch (error) {
        console.error("Google login failed", error);
        emit("login-error", error);
    }
}

function renderGoogleButton() {
    if (!buttonContainer.value) {
        return;
    }
    if (!window.google?.accounts?.id) {
        return;
    }
    if (!CLIENT_ID) {
        console.warn(
            "Missing VITE_GOOGLE_SSO_CLIENT_ID env variable; Google Sign-In is disabled."
        );
        emit("login-error", new Error("Google Sign-In 未設定客戶端 ID"));
        return;
    }

    buttonContainer.value.replaceChildren();
    window.google.accounts.id.initialize({
        client_id: CLIENT_ID,
        callback: handleCredentialResponse,
    });
    window.google.accounts.id.renderButton(buttonContainer.value, {
        type: "standard",
        size: "large",
        theme: "outline",
        text: "sign_in_with",
        shape: "rectangular",
        logo_alignment: "center",
    });
    window.google.accounts.id.prompt();
}

onMounted(async () => {
    if (typeof window === "undefined") {
        return;
    }

    try {
        await loadGoogleIdentityServices();
        renderGoogleButton();
    } catch (error) {
        console.error(error);
        emit("login-error", error);
    }
});
</script>

<template>
    <div class="google-btn-container">
        <div ref="buttonContainer"></div>
    </div>
</template>

<style scoped>
.google-btn-container {
    width: 100%;
    display: flex;
    justify-content: center;
    align-items: center;
    padding: 0.5rem 0;
}
</style>
