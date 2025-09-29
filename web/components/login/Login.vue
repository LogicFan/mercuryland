<script setup lang="ts">
import { computed, onMounted, onUnmounted, reactive, ref } from "vue";
import { VaButton, VaModal } from "vuestic-ui";
import axios from "axios";
import { BASE_URL } from "@/composables/utils";
import GoogleSso from "@/components/login/GoogleSso.vue";

interface SessionResponse {
    token: string;
    email?: string;
    name?: string;
}

const clientIp = ref<string | null>(null);

const modal = reactive({
    show: false,
    auth: false,
    fail: false,
});

const session = reactive({
    email: null as string | null,
    name: null as string | null,
});

const sessionDisplayName = computed(
    () => session.name ?? session.email ?? "已登入"
);

async function fetchClientIp() {
    try {
        const response = await fetch("https://api.ipify.org?format=json");
        const data = await response.json();
        clientIp.value = data?.ip ?? null;
    } catch (error) {
        console.error("Error fetching IP address:", error);
        clientIp.value = null;
    }
}

onMounted(fetchClientIp);

function clearSession() {
    session.email = null;
    session.name = null;
    modal.auth = false;
}

async function logout() {
    const email = session.email;
    localStorage.removeItem("token");
    clearSession();
    modal.show = false;

    console.log(
        `[LOGOUT] User ${email ?? "unknown"} logged out on ${new Date().toISOString()} at ${
            clientIp.value ?? "unknown"
        }.`
    );

    try {
        await axios.post(BASE_URL + "/api/auth/logout", {
            email,
            ip: clientIp.value ?? null,
        });
    } catch (error) {
        console.error("Failed to log logout event", error);
    }
}

function applySession(response: SessionResponse) {
    localStorage.setItem("token", response.token);
    session.email = response.email ?? null;
    session.name = response.name ?? response.email ?? null;
    modal.auth = true;
    modal.show = false;
    modal.fail = false;
}

function handleLoginSuccess(response: SessionResponse) {
    applySession(response);
}

function handleLoginError(error: unknown) {
    console.error("Google login failed", error);
    modal.fail = true;
}

function tick() {
    const token = localStorage.getItem("token");
    if (!token) {
        clearSession();
        return;
    }

    axios
        .post<SessionResponse>(BASE_URL + "/api/auth/tick", {
            token,
        })
        .then((response) => {
            applySession(response.data);
        })
        .catch(() => {
            localStorage.removeItem("token");
            clearSession();
        });
}

tick();
const tickInterval = setInterval(() => {
    tick();
}, 1000 * 60 * 10);

onUnmounted(() => {
    clearInterval(tickInterval);
});
</script>

<template>
    <template v-if="modal.auth">
        <div class="flex items-center gap-2">
            <span>{{ sessionDisplayName }}</span>
        </div>
        <VaButton @click="modal.show = true">登出</VaButton>
        <VaModal v-model="modal.show" @ok="logout">
            <div>您确定要登出吗?</div>
        </VaModal>
    </template>
    <template v-else>
        <VaButton @click="modal.show = true">登入</VaButton>
        <VaModal v-model="modal.show" hide-default-actions close-button max-width="400px">
            <div class="h-full flex items-center justify-center py-4">
                <div class="flex w-full flex-col items-center gap-3">
                    <p
                        v-if="modal.fail"
                        class="px-4 text-center text-sm text-red-500"
                    >
                        Google 登入失敗，請稍後再試。
                    </p>
                    <GoogleSso
                        v-if="!modal.auth"
                        :client-ip="clientIp"
                        @login-success="handleLoginSuccess"
                        @login-error="handleLoginError"
                    />
                </div>
            </div>
        </VaModal>
    </template>
</template>

<style scoped></style>
