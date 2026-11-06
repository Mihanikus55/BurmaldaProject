// ============================================================================
// ЕДИНОЕ РЕАКТИВНОЕ СОСТОЯНИЕ И КЛИЕНТСКИЙ КОНТРОЛЛЕР (VANILLA JS)
// ============================================================================
const uiState = {
    darkMode: true,
    unitMode: 'both',      // 'rub' | 'kop' | 'both'
    viewTab: 'split',      // 'split' | 'client' | 'bookmaker' | 'regulator' | 'arbiter'
    currentStep: 0,
    selectedSqlTable: 'links',
    soloErrorAlert: null,
    formName: 'Иванов Иван Иванович',
    formPassport: '4018 123456',
    formAge: 23,
    stakeRub: 1000,
    selection: 'HOME_WIN',
    courtOrder: 'Судебный ордер №42 (Проверка AML)',
    serverData: null
};

const stepsMeta = [
    { num: 1, title: 'Шаг 1: Регистрация (KYC)', sub: 'Разделение DEK на 3 доли + BBS+' },
    { num: 2, title: 'Шаг 2: Депозит и Ликвидность', sub: 'Клиент 3 000 ₽ | БК 10 000 ₽' },
    { num: 3, title: 'Шаг 3: Ставка 1 000 ₽ @ 2.40', sub: 'Холд 1 000 ₽ + Риск БК 1 400 ₽' },
    { num: 4, title: 'Шаг 4: Расчёт (Победа А)', sub: 'Выплата из Эскроу: Баланс 4 400 ₽' },
    { num: 5, title: 'Шаг 5: Раскрытие «2 из 3»', sub: 'Отказ 403 (1/3) → Ордер Арбитра (2/3)' }
];

function formatMoney(kopecks, mode = uiState.unitMode) {
    const rub = (kopecks / 100).toLocaleString('ru-RU', {
        minimumFractionDigits: kopecks % 100 === 0 ? 0 : 2,
        maximumFractionDigits: 2
    });
    const kop = kopecks.toLocaleString('ru-RU');
    if (mode === 'rub') return `${rub} ₽`;
    if (mode === 'kop') return `${kop} коп.`;
    return `${rub} ₽ (${kop} коп.)`;
}

function triggerPacketFlow(from, to, label) {
    const banner = document.getElementById('packet-flow-banner');
    document.getElementById('pf-from').textContent = from;
    document.getElementById('pf-to').textContent = to;
    document.getElementById('pf-label').textContent = label;
    banner.classList.remove('hidden');
    clearTimeout(window._pfTimer);
    window._pfTimer = setTimeout(() => {
        banner.classList.add('hidden');
    }, 1800);
}

// ============================================================================
// СИНХРОНИЗАЦИЯ С FLASK BACKEND (/api/state)
// ============================================================================
async function syncState() {
    const res = await fetch('/api/state');
    uiState.serverData = await res.json();
    renderAll();
}

// ============================================================================
// ДЕЙСТВИЯ ПОЛЬЗОВАТЕЛЯ И ВЫЗОВЫ BLUEPRINT МИКРОСЕРВИСОВ
// ============================================================================
async function handleRegister() {
    const nameEl = document.getElementById('inp-name');
    const passEl = document.getElementById('inp-passport');
    const ageEl = document.getElementById('inp-age');
    if (nameEl) uiState.formName = nameEl.value;
    if (passEl) uiState.formPassport = passEl.value;
    if (ageEl) uiState.formAge = Number(ageEl.value);

    uiState.soloErrorAlert = null;
    triggerPacketFlow('Client (:5003)', 'Regulator (:5001)', 'POST /api/client/register (KYC + Shamir 2-of-3 Split)');

    await fetch('/api/client/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            full_name: uiState.formName,
            passport: uiState.formPassport,
            age: uiState.formAge
        })
    });
    uiState.currentStep = Math.max(uiState.currentStep, 1);
    await syncState();
}

async function handleDepositAndLiquidity() {
    if (!uiState.serverData?.wallet?.registered) {
        await handleRegister();
    }
    triggerPacketFlow('Client & Bookmaker', 'Regulator (:5001)', 'POST /api/client/step2-deposit-all (3 000 ₽ + 10 000 ₽ Эскроу)');
    await fetch('/api/client/step2-deposit-all', { method: 'POST' });
    uiState.currentStep = Math.max(uiState.currentStep, 2);
    await syncState();
}

async function handleSingleClientDeposit(amountKop) {
    triggerPacketFlow('Client (:5003)', 'Regulator (:5001)', `POST /api/regulator/accounts/deposit (+${amountKop / 100} ₽)`);
    const cid = uiState.serverData.wallet.clientId;
    await fetch('/api/regulator/accounts/deposit', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ owner_ref: `client:${cid}`, amount: amountKop })
    });
    await syncState();
}

async function handleTopUpLiquidity(amountKop) {
    triggerPacketFlow('Bookmaker (:5002)', 'Regulator (:5001)', `POST /api/bookmaker/liquidity/top-up (+${amountKop / 100} ₽)`);
    await fetch('/api/bookmaker/liquidity/top-up', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ amount: amountKop })
    });
    await syncState();
}

async function handlePlaceBet(customSel, customStakeKop) {
    const selEl = document.getElementById('inp-selection');
    const stakeEl = document.getElementById('inp-stake');
    if (selEl) uiState.selection = selEl.value;
    if (stakeEl) uiState.stakeRub = Number(stakeEl.value);

    const selection = customSel || uiState.selection;
    const stakeKop = customStakeKop || (uiState.stakeRub * 100);
    const odds = selection === 'HOME_WIN' ? 2.40 : 1.65;
    const bkRisk = Math.round(stakeKop * odds) - stakeKop;

    triggerPacketFlow(
        'Client (:5003) → Bookmaker (:5002) → Regulator (:5001)',
        'Escrow Engine',
        `Ставка ${stakeKop / 100} ₽ @ ${odds.toFixed(2)} (Холд клиента: ${stakeKop / 100} ₽, Холд риска БК: ${bkRisk / 100} ₽)`
    );

    const res = await fetch('/api/client/place-bet', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ selection, stake: stakeKop })
    });
    if (res.ok) {
        uiState.currentStep = Math.max(uiState.currentStep, 3);
    }
    await syncState();
}

async function handleSettleEvent(outcome = 'HOME_WIN') {
    triggerPacketFlow('Regulator (:5001)', 'Client & Bookmaker', `POST /api/regulator/events/outcome (${outcome}) — Авто-клиринг холдов`);
    await fetch('/api/regulator/events/outcome', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ outcome })
    });
    uiState.currentStep = Math.max(uiState.currentStep, 4);
    await syncState();
}

async function handleSoloDisclosureAttempt() {
    triggerPacketFlow('Regulator (:5001)', 'Custody Vault', 'POST /api/regulator/disclosures/solo-attempt (Попытка расшифровать 1 долей...)');
    const res = await fetch('/api/regulator/disclosures/solo-attempt', { method: 'POST' });
    const data = await res.json();
    if (res.status === 403) {
        uiState.soloErrorAlert = data.message;
    }
    uiState.currentStep = Math.max(uiState.currentStep, 5);
    await syncState();
}

async function handleArbiterApprove(customReason) {
    const orderEl = document.getElementById('inp-court-order');
    if (orderEl) uiState.courtOrder = orderEl.value;
    const reason = customReason || uiState.courtOrder;

    triggerPacketFlow('Arbiter (:5004)', 'Regulator (:5001)', `POST /api/arbiter/disclosures/approve (Передача доли #3: ${reason})`);
    uiState.soloErrorAlert = null;
    await fetch('/api/arbiter/disclosures/approve', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ reason })
    });
    await syncState();
}

async function handleArbiterDeny() {
    await fetch('/api/arbiter/disclosures/deny', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ reason: 'Отсутствует судебное основание' })
    });
    await syncState();
}

async function handleClientVoluntaryDisclosure() {
    triggerPacketFlow('Client (:5003)', 'Regulator (:5001)', 'POST /api/client/disclosures/approve (Добровольная передача доли #1)');
    uiState.soloErrorAlert = null;
    await fetch('/api/client/disclosures/approve', { method: 'POST' });
    await syncState();
}

async function handleResetDemo() {
    uiState.soloErrorAlert = null;
    uiState.currentStep = 0;
    await fetch('/api/reset', { method: 'POST' });
    await syncState();
}

async function executeStep(stepNum) {
    if (stepNum === 1) {
        await handleRegister();
    } else if (stepNum === 2) {
        await handleDepositAndLiquidity();
    } else if (stepNum === 3) {
        if ((uiState.serverData?.accounts?.client?.available || 0) < 1000_00) {
            await handleDepositAndLiquidity();
        }
        await handlePlaceBet('HOME_WIN', 1000_00);
    } else if (stepNum === 4) {
        await handleSettleEvent('HOME_WIN');
    } else if (stepNum === 5) {
        if (!uiState.serverData?.wallet?.registered) {
            await handleRegister();
        }
        await handleSoloDisclosureAttempt();
    }
}

// ============================================================================
// УПРАВЛЕНИЕ ВИДОМ, ВАЛЮТОЙ И ТЕМОЙ
// ============================================================================
function setUnitMode(mode) {
    uiState.unitMode = mode;
    document.querySelectorAll('.unit-btn').forEach((btn) => {
        if (btn.dataset.unit === mode) {
            btn.className = 'unit-btn px-2.5 py-1 rounded-md font-semibold transition cursor-pointer bg-indigo-600 text-white';
        } else {
            btn.className = 'unit-btn px-2.5 py-1 rounded-md font-semibold transition cursor-pointer text-slate-400 hover:text-white';
        }
    });
    renderAll();
}

function setViewTab(tab) {
    uiState.viewTab = tab;
    document.querySelectorAll('.tab-btn').forEach((btn) => {
        if (btn.dataset.tab === tab) {
            btn.className = 'tab-btn px-3 py-1.5 rounded-lg text-xs font-bold flex items-center gap-1.5 transition cursor-pointer bg-indigo-600 text-white shadow';
        } else {
            btn.className = 'tab-btn px-3 py-1.5 rounded-lg text-xs font-bold flex items-center gap-1.5 transition cursor-pointer text-slate-400 hover:text-white';
        }
    });
    renderAll();
}

function setSelectedSqlTable(tbl) {
    uiState.selectedSqlTable = tbl;
    renderPrivacyMatrix();
}

function toggleTheme() {
    uiState.darkMode = !uiState.darkMode;
    const body = document.getElementById('app-body');
    const btn = document.getElementById('theme-toggle-btn');
    if (uiState.darkMode) {
        body.classList.remove('light-mode');
        btn.textContent = '☀️';
    } else {
        body.classList.add('light-mode');
        btn.textContent = '🌙';
    }
    renderAll();
}

// ============================================================================
// ФУНКЦИИ РЕАКТИВНОЙ ОТРИСОВКИ КОМПОНЕНТОВ ДАШБОРДА
// ============================================================================
function renderStepper() {
    const container = document.getElementById('stepper-grid');
    container.innerHTML = stepsMeta.map((st) => {
        const isDone = uiState.currentStep >= st.num;
        const isCurrent = uiState.currentStep === st.num;
        const borderCls = isCurrent
            ? 'bg-indigo-600/20 border-indigo-500 ring-2 ring-indigo-500/40'
            : isDone
            ? 'bg-emerald-950/30 border-emerald-500/40'
            : 'sub-box bg-slate-800/60 border-slate-700/70 hover:bg-slate-800';
        const titleColor = isCurrent ? 'text-indigo-400' : isDone ? 'text-emerald-400' : 'text-slate-300';
        const icon = isDone ? '✅' : '›';
        return `
            <button onclick="executeStep(${st.num})" class="p-3 rounded-xl border text-left transition-all cursor-pointer flex flex-col justify-between ${borderCls}">
                <div class="flex items-center justify-between w-full mb-1">
                    <span class="text-xs font-extrabold ${titleColor}">${st.title}</span>
                    <span class="text-xs">${icon}</span>
                </div>
                <div class="text-[11px] text-slate-400">${st.sub}</div>
            </button>
        `;
    }).join('');
}

function renderBanners() {
    const errBanner = document.getElementById('solo-error-banner');
    const errText = document.getElementById('solo-error-text');
    if (uiState.soloErrorAlert) {
        errText.textContent = uiState.soloErrorAlert;
        errBanner.classList.remove('hidden');
    } else {
        errBanner.classList.add('hidden');
    }

    const revBanner = document.getElementById('revealed-success-banner');
    const disc = uiState.serverData?.disclosure;
    if (disc && disc.status === 'REVEALED' && disc.revealedIdentity) {
        document.getElementById('revealed-title').textContent =
            `Порог «2 из 3» собран (${disc.collected.join(' + ')}) — Личность успешно расшифрована!`;
        document.getElementById('revealed-details').innerHTML =
            `Токен <span class="text-indigo-300 font-bold">${disc.subject}</span> принадлежит гражданину: ` +
            `<span class="text-white font-bold underline">${disc.revealedIdentity.full_name}</span> ` +
            `(Паспорт: ${disc.revealedIdentity.passport}, ID: ${disc.revealedIdentity.client_id})`;
        revBanner.classList.remove('hidden');
    } else {
        revBanner.classList.add('hidden');
    }
}

function renderEscrowVisualizer() {
    const d = uiState.serverData;
    const cAcc = d.accounts.client;
    const bkAcc = d.accounts.bookmaker;
    const holds = d.regulator.holds;
    const lastOutcome = d.regulator.lastOutcome;

    const cTotal = Math.max(cAcc.available + cAcc.held, 1);
    const bkTotal = Math.max(bkAcc.available + bkAcc.held, 1);

    const cAvailPct = cAcc.available + cAcc.held > 0 ? Math.round((cAcc.available / cTotal) * 100) : 0;
    const cHeldPct = cAcc.available + cAcc.held > 0 ? Math.round((cAcc.held / cTotal) * 100) : 0;
    const bkAvailPct = bkAcc.available + bkAcc.held > 0 ? Math.round((bkAcc.available / bkTotal) * 100) : 0;
    const bkHeldPct = bkAcc.available + bkAcc.held > 0 ? Math.round((bkAcc.held / bkTotal) * 100) : 0;

    let statusPill = `<span class="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-medium bg-slate-800 text-slate-400">Холдов нет</span>`;
    if (holds.length > 0) {
        statusPill = `<span class="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-semibold bg-amber-500/15 text-amber-400 border border-amber-500/30 animate-pulse">🔒 2 Активных Холда в Эскроу (Ставка 1 000 ₽ + Риск БК 1 400 ₽)</span>`;
    } else if (lastOutcome) {
        statusPill = `<span class="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-semibold bg-emerald-500/15 text-emerald-400 border border-emerald-500/30">✅ Клиринг завершён (${lastOutcome}) — Холды распределены</span>`;
    }

    document.getElementById('escrow-visualizer').innerHTML = `
        <div class="flex flex-wrap items-center justify-between gap-3 mb-4">
            <div class="flex items-center gap-2.5">
                <div class="p-2 rounded-lg bg-emerald-500/10 text-emerald-500 border border-emerald-500/20 font-bold">🪙</div>
                <div>
                    <h3 class="text-sm font-bold uppercase tracking-wider text-emerald-500">
                        Атомарный Эскроу-Монитор Холдов (Двойная запись int64)
                    </h3>
                    <p class="text-xs text-slate-400">
                        Гарантия выплаты: ставка принимается только при наличии обеспечения риска у букмекера
                    </p>
                </div>
            </div>
            <div>${statusPill}</div>
        </div>

        <div class="grid grid-cols-1 lg:grid-cols-2 gap-4">
            <!-- Счёт Клиента -->
            <div class="sub-box p-4 rounded-xl border bg-slate-800/60 border-amber-500/30">
                <div class="flex items-center justify-between mb-2">
                    <span class="text-xs font-bold uppercase tracking-wider text-amber-500">👛 Счёт Клиента: ${cAcc.owner_ref}</span>
                    <span class="text-xs font-mono px-2 py-0.5 rounded bg-amber-500/10 text-amber-400">v${cAcc.version}</span>
                </div>
                <div class="grid grid-cols-2 gap-3 my-3">
                    <div class="sub-box p-2.5 rounded-lg bg-slate-900/80">
                        <div class="text-[11px] text-slate-400">Доступно (Available)</div>
                        <div class="text-sm sm:text-base font-extrabold text-emerald-500 font-mono mt-0.5">${formatMoney(cAcc.available)}</div>
                    </div>
                    <div class="sub-box p-2.5 rounded-lg bg-slate-900/80">
                        <div class="text-[11px] text-slate-400">В холде ставки (Held)</div>
                        <div class="text-sm sm:text-base font-extrabold font-mono mt-0.5 ${cAcc.held > 0 ? 'text-amber-500' : 'text-slate-500'}">${formatMoney(cAcc.held)}</div>
                    </div>
                </div>
                <div class="w-full h-3 bg-slate-700/30 rounded-full overflow-hidden flex">
                    <div style="width: ${cAvailPct}%" class="bg-emerald-500 hold-bar-segment"></div>
                    <div style="width: ${cHeldPct}%" class="bg-amber-500 hold-bar-segment"></div>
                </div>
                <div class="flex justify-between text-[11px] mt-1.5 text-slate-400">
                    <span>Available: ${cAvailPct}%</span>
                    <span>Held (Ставка): ${cHeldPct}%</span>
                </div>
            </div>

            <!-- Счёт Обеспечения Букмекера -->
            <div class="sub-box p-4 rounded-xl border bg-slate-800/60 border-indigo-500/30">
                <div class="flex items-center justify-between mb-2">
                    <span class="text-xs font-bold uppercase tracking-wider text-indigo-400">🏢 Обеспечение БК: ${bkAcc.owner_ref}</span>
                    <span class="text-xs font-mono px-2 py-0.5 rounded bg-indigo-500/10 text-indigo-400">v${bkAcc.version}</span>
                </div>
                <div class="grid grid-cols-2 gap-3 my-3">
                    <div class="sub-box p-2.5 rounded-lg bg-slate-900/80">
                        <div class="text-[11px] text-slate-400">Доступная ликвидность</div>
                        <div class="text-sm sm:text-base font-extrabold text-indigo-400 font-mono mt-0.5">${formatMoney(bkAcc.available)}</div>
                    </div>
                    <div class="sub-box p-2.5 rounded-lg bg-slate-900/80">
                        <div class="text-[11px] text-slate-400">Холд риска (1000×2.40−1000)</div>
                        <div class="text-sm sm:text-base font-extrabold font-mono mt-0.5 ${bkAcc.held > 0 ? 'text-rose-400' : 'text-slate-500'}">${formatMoney(bkAcc.held)}</div>
                    </div>
                </div>
                <div class="w-full h-3 bg-slate-700/30 rounded-full overflow-hidden flex">
                    <div style="width: ${bkAvailPct}%" class="bg-indigo-500 hold-bar-segment"></div>
                    <div style="width: ${bkHeldPct}%" class="bg-rose-500 hold-bar-segment"></div>
                </div>
                <div class="flex justify-between text-[11px] mt-1.5 text-slate-400">
                    <span>Свободный пул: ${bkAvailPct}%</span>
                    <span>Замороженный риск БК: ${bkHeldPct}%</span>
                </div>
            </div>
        </div>
    `;
}

function renderClientPanel() {
    const w = uiState.serverData.wallet;
    const cAcc = uiState.serverData.accounts.client;
    const disc = uiState.serverData.disclosure;

    const kycBlock = !w.registered ? `
        <div class="grid grid-cols-1 sm:grid-cols-3 gap-2 text-xs">
            <input id="inp-name" value="${uiState.formName}" class="px-2.5 py-1.5 rounded border bg-slate-900 border-slate-700 text-white" placeholder="ФИО" />
            <input id="inp-passport" value="${uiState.formPassport}" class="px-2.5 py-1.5 rounded border font-mono bg-slate-900 border-slate-700 text-white" placeholder="Паспорт" />
            <input id="inp-age" type="number" value="${uiState.formAge}" class="px-2.5 py-1.5 rounded border font-mono bg-slate-900 border-slate-700 text-white" placeholder="Возраст" />
        </div>
    ` : `
        <div class="space-y-1.5 text-xs">
            <div class="flex justify-between"><span class="text-slate-400">Гражданская личность (локально):</span><span class="font-semibold">${w.fullName} (${w.passport})</span></div>
            <div class="flex justify-between"><span class="text-slate-400">Client ID (только для Регулятора):</span><span class="font-mono text-amber-400">${w.clientId}</span></div>
            <div class="flex justify-between"><span class="text-slate-400">Мастер-секрет s (CSPRNG 256-bit):</span><span class="font-mono text-emerald-400">${w.clientSecret}</span></div>
            <div class="flex justify-between"><span class="text-slate-400">Доля ключа #1 (Client Share):</span><span class="font-mono text-amber-300">${w.clientShare}</span></div>
            <div class="flex justify-between items-center pt-1">
                <span class="text-slate-400">BBS+ Справка Регулятора:</span>
                <span class="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-emerald-500/15 text-emerald-400 font-mono text-[11px]">✅ 18+: ДА | KYC: OK | ЛИМИТ: OK</span>
            </div>
        </div>
    `;

    const tokensBlock = w.registered ? `
        <div class="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs">
            <div class="sub-box p-2 rounded border bg-slate-900 border-indigo-500/30">
                <div class="text-[10px] text-slate-400">Для БК Alpha (bk_alpha):</div>
                <div class="font-mono font-bold text-indigo-400 mt-0.5">${w.tokens.bk_alpha}</div>
                <div class="text-[10px] font-mono text-slate-500 truncate mt-0.5">ZK: ${w.zkProofs.bk_alpha}</div>
            </div>
            <div class="sub-box p-2 rounded border bg-slate-900 border-purple-500/30">
                <div class="text-[10px] text-slate-400">Для БК Beta (bk_beta):</div>
                <div class="font-mono font-bold text-purple-400 mt-0.5">${w.tokens.bk_beta}</div>
                <div class="text-[10px] font-mono text-slate-500 truncate mt-0.5">ZK: ${w.zkProofs.bk_beta}</div>
            </div>
        </div>
    ` : `<p class="text-xs text-slate-400 italic">Пройдите регистрацию для деривации токенов P_B</p>`;

    const receiptsHtml = w.receipts.length === 0
        ? `<div class="text-xs text-slate-500 italic">Нет активных квитанций ставок</div>`
        : w.receipts.slice(0, 2).map((r) => `
            <div class="sub-box p-2 rounded border text-[11px] font-mono flex items-center justify-between bg-slate-950/70 border-slate-800">
                <div><span class="text-indigo-400 font-bold">${r.bet_id}</span> • ${r.selection} • ${formatMoney(r.stake, 'rub')} × ${r.odds}</div>
                <span class="text-emerald-400 truncate max-w-[160px]" title="${r.bookmaker_sig}">${r.bookmaker_sig}</span>
            </div>
        `).join('');

    const voluntaryBtn = (disc && disc.status !== 'REVEALED')
        ? `<button onclick="handleClientVoluntaryDisclosure()" class="px-2.5 py-1 rounded bg-amber-500/20 hover:bg-amber-500/30 text-amber-300 border border-amber-500/40 text-[11px] font-semibold transition cursor-pointer">Отдать свою долю #1 (Спор)</button>`
        : '';

    document.getElementById('panel-client').innerHTML = `
        <div class="p-4 border-b border-amber-500/20 bg-gradient-to-r from-amber-500/15 via-orange-500/5 to-transparent flex items-center justify-between">
            <div class="flex items-center gap-2.5">
                <div class="p-2 rounded-lg bg-amber-500 text-slate-950 font-bold">📱</div>
                <div>
                    <div class="flex items-center gap-2">
                        <h3 class="font-bold text-sm sm:text-base">1. Client Wallet (Кошелёк Клиента)</h3>
                        <span class="text-[11px] font-mono px-2 py-0.5 rounded bg-amber-500/20 text-amber-400 border border-amber-500/30">:5003</span>
                    </div>
                    <p class="text-xs text-slate-400">Единственное место хранения секрета s, доли ключа #1 и квитанций</p>
                </div>
            </div>
            <span class="text-xs font-mono px-2.5 py-1 rounded-full ${w.registered ? 'bg-emerald-500/15 text-emerald-400 border border-emerald-500/30' : 'bg-slate-500/15 text-slate-400'}">
                ${w.registered ? 'KYC АКТИВЕН' : 'НЕ ЗАРЕГИСТРИРОВАН'}
            </span>
        </div>

        <div class="p-4 space-y-4 flex-1 flex flex-col justify-between">
            <div class="space-y-3">
                <div class="sub-box p-3 rounded-lg border bg-slate-800/70 border-slate-700">
                    <div class="flex items-center justify-between mb-2">
                        <span class="text-xs font-bold uppercase text-amber-500">🔑 Профиль и Локальные Ключи (CSPRNG + Shamir)</span>
                        ${!w.registered ? `<button onclick="handleRegister()" class="px-3 py-1 rounded-lg bg-amber-500 hover:bg-amber-400 text-slate-950 font-bold text-xs transition cursor-pointer">Пройти KYC (Шаг 1)</button>` : ''}
                    </div>
                    ${kycBlock}
                </div>

                <div class="sub-box p-3 rounded-lg border bg-slate-800/70 border-slate-700">
                    <div class="text-xs font-bold uppercase text-amber-500 mb-1.5 flex items-center justify-between">
                        <span>✨ Несвязываемые Токены (P_B = s · H_B на Ristretto255)</span>
                        <span class="text-[10px] font-normal text-slate-400">Защита от сговора БК</span>
                    </div>
                    ${tokensBlock}
                </div>

                <div class="sub-box p-3 rounded-lg border bg-slate-800/70 border-slate-700">
                    <div class="flex items-center justify-between mb-2">
                        <span class="text-xs font-bold uppercase text-amber-500">Управление балансом и ставкой</span>
                        <button onclick="handleSingleClientDeposit(300000)" ${!w.registered ? 'disabled' : ''} class="px-2.5 py-1 rounded bg-emerald-600 hover:bg-emerald-500 disabled:opacity-40 text-white text-xs font-semibold transition cursor-pointer">
                            + Депозит 3 000 ₽
                        </button>
                    </div>
                    <div class="grid grid-cols-1 sm:grid-cols-3 gap-2 items-center text-xs mt-2">
                        <div>
                            <label class="block text-[10px] text-slate-400 mb-0.5">Исход финала:</label>
                            <select id="inp-selection" class="w-full px-2 py-1.5 rounded border font-semibold bg-slate-900 border-slate-700 text-white">
                                <option value="HOME_WIN" ${uiState.selection === 'HOME_WIN' ? 'selected' : ''}>HOME_WIN (Кэф 2.40)</option>
                                <option value="AWAY_WIN" ${uiState.selection === 'AWAY_WIN' ? 'selected' : ''}>AWAY_WIN (Кэф 1.65)</option>
                            </select>
                        </div>
                        <div>
                            <label class="block text-[10px] text-slate-400 mb-0.5">Сумма ставки (₽):</label>
                            <input id="inp-stake" type="number" value="${uiState.stakeRub}" class="w-full px-2 py-1.5 rounded border font-mono bg-slate-900 border-slate-700 text-white" />
                        </div>
                        <div class="pt-3.5">
                            <button onclick="handlePlaceBet()" ${(!w.registered || cAcc.available < uiState.stakeRub * 100) ? 'disabled' : ''} class="w-full py-1.5 px-3 rounded-lg bg-indigo-600 hover:bg-indigo-500 disabled:opacity-40 text-white font-bold text-xs transition cursor-pointer">
                                Поставить под токеном
                            </button>
                        </div>
                    </div>
                </div>
            </div>

            <div class="space-y-2 pt-2 border-t border-slate-700/40">
                <div class="flex items-center justify-between text-xs">
                    <span class="font-semibold text-slate-400">Квитанции букмекера (${w.receipts.length}):</span>
                    ${voluntaryBtn}
                </div>
                ${receiptsHtml}
            </div>
        </div>
    `;
}

function renderBookmakerPanel() {
    const bm = uiState.serverData.bookmaker;
    const expHtml = bm.exposures.length === 0
        ? `<div class="text-xs text-slate-400 italic py-2">Ставок пока нет — экспозиция по токенам пуста</div>`
        : `
            <div class="overflow-x-auto">
                <table class="w-full text-left text-xs">
                    <thead>
                        <tr class="border-b border-slate-700/50 text-[11px] text-slate-400">
                            <th class="pb-1.5">Токен (Псевдоним)</th>
                            <th class="pb-1.5">Ставок</th>
                            <th class="pb-1.5">Оборот</th>
                            <th class="pb-1.5">Выигрышей</th>
                            <th class="pb-1.5">ФИО владельца</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${bm.exposures.map((exp) => `
                            <tr class="border-b border-slate-800/40 font-mono">
                                <td class="py-1.5 text-indigo-400 font-bold">${exp.token}</td>
                                <td class="py-1.5">${exp.bets_count}</td>
                                <td class="py-1.5">${formatMoney(exp.total_staked)}</td>
                                <td class="py-1.5 text-emerald-400 font-bold">${exp.won_count}</td>
                                <td class="py-1.5"><span class="px-1.5 py-0.5 rounded bg-slate-700/50 text-slate-400 text-[10px]">🔒 НЕИЗВЕСТНО</span></td>
                            </tr>
                        `).join('')}
                    </tbody>
                </table>
            </div>
        `;

    const betsHtml = bm.bets.length === 0
        ? `<div class="text-xs text-slate-500 italic">Нет зарегистрированных ставок</div>`
        : bm.bets.slice(0, 2).map((b) => {
            const stCls = b.status === 'SETTLED_WON'
                ? 'bg-emerald-500/20 text-emerald-400'
                : b.status === 'SETTLED_LOST'
                ? 'bg-rose-500/20 text-rose-400'
                : 'bg-amber-500/20 text-amber-400';
            return `
                <div class="sub-box p-2 rounded border text-[11px] font-mono flex flex-wrap items-center justify-between gap-2 bg-slate-950/70 border-slate-800">
                    <div><span class="text-indigo-400 font-bold">${b.token}</span> → ${b.selection} (Кэф ${b.odds})</div>
                    <div class="flex items-center gap-2">
                        <span class="text-slate-400">Commit: 0x${b.odds_commitment.slice(0, 10)}…</span>
                        <span class="px-2 py-0.5 rounded text-[10px] font-bold ${stCls}">${b.status}</span>
                    </div>
                </div>
            `;
        }).join('');

    document.getElementById('panel-bookmaker').innerHTML = `
        <div class="p-4 border-b border-indigo-500/20 bg-gradient-to-r from-indigo-500/15 via-blue-500/5 to-transparent flex items-center justify-between">
            <div class="flex items-center gap-2.5">
                <div class="p-2 rounded-lg bg-indigo-600 text-white font-bold">🏢</div>
                <div>
                    <div class="flex items-center gap-2">
                        <h3 class="font-bold text-sm sm:text-base">2. Bookmaker Service (Букмекер Alpha)</h3>
                        <span class="text-[11px] font-mono px-2 py-0.5 rounded bg-indigo-500/20 text-indigo-400 border border-indigo-500/30">:5002</span>
                    </div>
                    <p class="text-xs text-slate-400">Видит ТОЛЬКО токен. Считает коэффициенты и риск-профиль без знания ФИО</p>
                </div>
            </div>
            <button onclick="handleTopUpLiquidity(1000000)" class="px-3 py-1.5 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white font-bold text-xs transition cursor-pointer">
                + Внести 10 000 ₽ в Эскроу
            </button>
        </div>

        <div class="p-4 space-y-4 flex-1 flex flex-col justify-between">
            <div class="space-y-3">
                <div class="sub-box p-3 rounded-lg border flex items-center justify-between bg-slate-950/90 border-rose-500/30">
                    <div class="text-xs">
                        <span class="font-bold text-rose-400">🚫 Персональные данные игрока (ФИО, Паспорт, Карта):</span>
                        <div class="text-[11px] text-slate-400">В базе букмекера физически отсутствуют колонки ПДн</div>
                    </div>
                    <span class="crypto-blur-badge px-2.5 py-1 rounded bg-rose-500/15 text-rose-400 border border-rose-500/30 font-mono text-xs font-bold">
                        🔒 Скрыто криптографией
                    </span>
                </div>

                <div class="sub-box p-3 rounded-lg border bg-slate-800/70 border-slate-700">
                    <div class="flex items-center justify-between mb-2">
                        <span class="text-xs font-bold uppercase text-indigo-400">📈 Линия и Движок Коэффициентов (Pricing Engine)</span>
                        <span class="text-[11px] font-mono text-slate-400">ID: ev_final_2026</span>
                    </div>
                    <div class="text-xs font-semibold mb-2">Финал Кубка: Команда А vs Команда Б</div>
                    <div class="grid grid-cols-2 gap-2 text-xs">
                        <div class="sub-box p-2 rounded border flex justify-between items-center bg-slate-900 border-slate-700">
                            <span>Победа 1 (HOME_WIN)</span>
                            <span class="font-mono font-extrabold text-indigo-400 text-sm">2.40</span>
                        </div>
                        <div class="sub-box p-2 rounded border flex justify-between items-center bg-slate-900 border-slate-700">
                            <span>Победа 2 (AWAY_WIN)</span>
                            <span class="font-mono font-extrabold text-indigo-400 text-sm">1.65</span>
                        </div>
                    </div>
                </div>

                <div class="sub-box p-3 rounded-lg border bg-slate-800/70 border-slate-700">
                    <div class="text-xs font-bold uppercase text-indigo-400 mb-2 flex items-center justify-between">
                        <span>Таблица Риск-Профилей по Токенам (bm_token_exposure)</span>
                        <span class="text-[10px] font-normal text-slate-400">Скоринг по псевдониму</span>
                    </div>
                    ${expHtml}
                </div>
            </div>

            <div class="pt-2 border-t border-slate-700/40 space-y-1.5">
                <div class="text-xs font-semibold text-slate-400">Журнал ставок БК и крипто-обязательств коэффициента (bm_bets):</div>
                ${betsHtml}
            </div>
        </div>
    `;
}

function renderRegulatorPanel() {
    const reg = uiState.serverData.regulator;
    const linksHtml = reg.links.length === 0
        ? `<div class="text-xs text-slate-400 italic">Таблица links пуста — зарегистрируйте клиента</div>`
        : reg.links.map((lk) => `
            <div class="sub-box p-2 rounded border text-xs font-mono flex flex-wrap items-center justify-between gap-2 bg-slate-950/80 border-slate-800">
                <div><span class="text-emerald-400 font-bold">${lk.token}</span> <span class="text-slate-500 mx-1">↔</span> <span class="text-slate-400">BK: ${lk.bookmaker_id}</span></div>
                <span class="px-2 py-0.5 rounded bg-slate-800 text-amber-300 text-[11px] truncate max-w-[250px]">🔒 ${lk.client_ref_sealed}</span>
            </div>
        `).join('');

    const ledgerHtml = reg.ledger.length === 0
        ? `<div class="text-xs text-slate-400 italic">Проводок пока нет</div>`
        : reg.ledger.slice(0, 6).map((entry) => `
            <div class="flex items-center justify-between text-[11px] font-mono border-b border-slate-700/30 pb-1">
                <span class="text-slate-400">${entry.tx_id}</span>
                <span>${entry.account_id}</span>
                <span class="font-bold ${entry.direction === 'CREDIT' ? 'text-emerald-400' : 'text-rose-400'}">
                    ${entry.direction === 'CREDIT' ? '+' : '−'}${formatMoney(entry.amount)}
                </span>
            </div>
        `).join('');

    document.getElementById('panel-regulator').innerHTML = `
        <div class="p-4 border-b border-emerald-500/20 bg-gradient-to-r from-emerald-500/15 via-teal-500/5 to-transparent flex items-center justify-between">
            <div class="flex items-center gap-2.5">
                <div class="p-2 rounded-lg bg-emerald-600 text-white font-bold">🛡️</div>
                <div>
                    <div class="flex items-center gap-2">
                        <h3 class="font-bold text-sm sm:text-base">3. Regulator Service (Регулятор &amp; Эскроу)</h3>
                        <span class="text-[11px] font-mono px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-400 border border-emerald-500/30">:5001</span>
                    </div>
                    <p class="text-xs text-slate-400">Зашифрованная таблица links, двойная запись, клиринг исходов и аудит-цепочка</p>
                </div>
            </div>
            <button onclick="handleSoloDisclosureAttempt()" ${reg.links.length === 0 ? 'disabled' : ''} class="px-3 py-1.5 rounded-lg bg-rose-600/90 hover:bg-rose-500 disabled:opacity-40 text-white font-bold text-xs transition cursor-pointer">
                🔓 Попытка раскрыть в одиночку (1/3)
            </button>
        </div>

        <div class="p-4 space-y-4 flex-1 flex flex-col justify-between">
            <div class="space-y-3">
                <div class="sub-box p-3 rounded-lg border bg-slate-800/70 border-slate-700 space-y-1.5">
                    <div class="flex items-center justify-between mb-1">
                        <span class="text-xs font-bold uppercase text-emerald-400">🔒 Таблица зашифрованных связей (links: AES-256-GCM)</span>
                        <span class="text-[11px] font-mono text-emerald-400">Доля Регулятора: ${reg.regulatorShare || 'нет'}</span>
                    </div>
                    ${linksHtml}
                </div>

                <div class="sub-box p-3 rounded-lg border bg-slate-800/70 border-slate-700">
                    <div class="flex items-center justify-between mb-2">
                        <span class="text-xs font-bold uppercase text-emerald-400">Консоль Оракула Исходов и Авто-Клиринга (/api/regulator/events/outcome)</span>
                        <span class="text-[11px] font-mono text-slate-400">Статус: ${reg.eventStatus}</span>
                    </div>
                    <div class="grid grid-cols-3 gap-2">
                        <button onclick="handleSettleEvent('HOME_WIN')" class="py-1.5 px-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white font-bold text-xs transition cursor-pointer">Победа 1 (HOME_WIN)</button>
                        <button onclick="handleSettleEvent('AWAY_WIN')" class="py-1.5 px-2 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white font-bold text-xs transition cursor-pointer">Победа 2 (AWAY_WIN)</button>
                        <button onclick="handleSettleEvent('VOID')" class="py-1.5 px-2 rounded-lg bg-slate-600 hover:bg-slate-500 text-white font-bold text-xs transition cursor-pointer">Отмена (VOID — Возврат)</button>
                    </div>
                </div>

                <div class="sub-box p-3 rounded-lg border bg-slate-800/70 border-slate-700">
                    <div class="text-xs font-bold uppercase text-emerald-400 mb-1.5 flex items-center justify-between">
                        <span>Двойная Бухгалтерская Книга (ledger_entries)</span>
                        <span class="text-[10px] font-mono text-slate-400">∑ DEBIT + CREDIT = 0</span>
                    </div>
                    <div class="max-h-28 overflow-y-auto space-y-1 pr-1">${ledgerHtml}</div>
                </div>
            </div>

            <div class="pt-2 border-t border-slate-700/40 flex items-center justify-between text-xs font-mono">
                <span class="text-slate-400"># Audit Root (seq #${reg.auditLogs.length}):</span>
                <span class="text-emerald-400 truncate max-w-[240px]">0x${reg.auditRoot.slice(0, 24)}…</span>
            </div>
        </div>
    `;
}

function renderArbiterPanel() {
    const arb = uiState.serverData.arbiter;
    const disc = uiState.serverData.disclosure;

    const shareBlock = arb.storedShare ? `
        <div class="text-xs space-y-1 font-mono">
            <div class="flex justify-between"><span class="text-slate-400">Субъект депонирования:</span><span class="text-purple-300">${arb.clientId}</span></div>
            <div class="flex justify-between"><span class="text-slate-400">Резервная доля #3 (Arbiter Share):</span><span class="text-emerald-400">${arb.storedShare}</span></div>
        </div>
    ` : `<div class="text-xs text-slate-400 italic">Резервные доли ещё не поступали</div>`;

    const discBlock = !disc
        ? `<div class="text-xs text-slate-400 italic py-2">Активных запросов на раскрытие личности нет</div>`
        : `
            <div class="space-y-2.5 text-xs">
                <div class="flex flex-wrap justify-between gap-2">
                    <span>Запрос <strong class="font-mono text-purple-300">${disc.id}</strong> по токену <strong class="font-mono text-indigo-400">${disc.subject}</strong></span>
                    <span class="font-mono text-[11px] px-2 py-0.5 rounded bg-amber-500/20 text-amber-300">
                        Собрано долей: ${disc.collected.length} из 2 (${disc.collected.join(', ')})
                    </span>
                </div>
                <div>
                    <label class="block text-[10px] text-slate-400 mb-1">Основание для передачи доли #3 (протоколируется в хэш-цепочке):</label>
                    <input id="inp-court-order" value="${uiState.courtOrder}" class="w-full px-2.5 py-1.5 rounded border text-xs bg-slate-900 border-slate-700 text-white" />
                </div>
                <div class="flex gap-2">
                    <button onclick="handleArbiterApprove()" ${disc.status === 'REVEALED' ? 'disabled' : ''} class="flex-1 py-1.5 px-3 rounded-lg bg-purple-600 hover:bg-purple-500 disabled:opacity-40 text-white font-bold text-xs transition cursor-pointer">
                        ✅ Одобрить и передать долю #3
                    </button>
                    <button onclick="handleArbiterDeny()" ${disc.status === 'REVEALED' ? 'disabled' : ''} class="py-1.5 px-3 rounded-lg bg-rose-600/20 hover:bg-rose-600/30 disabled:opacity-40 text-rose-400 border border-rose-500/30 font-bold text-xs transition cursor-pointer">
                        Отклонить
                    </button>
                </div>
            </div>
        `;

    const auditHtml = arb.audit.length === 0
        ? `<div class="text-xs text-slate-500 italic">Обращений к арбитру не зафиксировано</div>`
        : arb.audit.slice(0, 2).map((a) => `
            <div class="text-[11px] font-mono text-purple-300 truncate">[${a.ts}] ${a.action}: ${a.details}</div>
        `).join('');

    document.getElementById('panel-arbiter').innerHTML = `
        <div class="p-4 border-b border-purple-500/20 bg-gradient-to-r from-purple-500/15 via-violet-500/5 to-transparent flex items-center justify-between">
            <div class="flex items-center gap-2.5">
                <div class="p-2 rounded-lg bg-purple-600 text-white font-bold">⚖️</div>
                <div>
                    <div class="flex items-center gap-2">
                        <h3 class="font-bold text-sm sm:text-base">4. Arbiter Service (Независимый Арбитр)</h3>
                        <span class="text-[11px] font-mono px-2 py-0.5 rounded bg-purple-500/20 text-purple-400 border border-purple-500/30">:5004</span>
                    </div>
                    <p class="text-xs text-slate-400">Хранит резервную долю #3. Одобряет раскрытие по судебному ордеру или при утере ключа</p>
                </div>
            </div>
            <span class="text-xs font-mono px-2.5 py-1 rounded-full bg-purple-500/15 text-purple-400 border border-purple-500/30">ПОРОГ 2 ИЗ 3</span>
        </div>

        <div class="p-4 space-y-4 flex-1 flex flex-col justify-between">
            <div class="space-y-3">
                <div class="sub-box p-3 rounded-lg border bg-slate-800/70 border-slate-700">
                    <div class="text-xs font-bold uppercase text-purple-400 mb-1.5">🔑 Депозитарий Третьей Доли Ключа (arbiter_shares)</div>
                    ${shareBlock}
                </div>
                <div class="sub-box p-3 rounded-lg border ${disc ? 'bg-purple-950/30 border-purple-500/40' : 'bg-slate-800/70 border-slate-700'}">
                    <div class="text-xs font-bold uppercase text-purple-400 mb-2">Входящие запросы на деанонимизацию (/api/arbiter/disclosures)</div>
                    ${discBlock}
                </div>
            </div>
            <div class="pt-2 border-t border-slate-700/40 space-y-1">
                <div class="text-xs font-semibold text-slate-400">Журнал решений Арбитра (${arb.audit.length}):</div>
                ${auditHtml}
            </div>
        </div>
    `;
}

function renderPrivacyMatrix() {
    const s = uiState.serverData;
    const tokAlpha = s.wallet.tokens.bk_alpha || 'P_BK_ALPHA_9F2B3C';
    const isRevealed = s.disclosure?.status === 'REVEALED';

    const matrixRows = [
        {
            field: 'Содержание ставки, сумма (1 000 ₽) и коэффициент (2.40)',
            bm: { ok: true, val: 'HOME_WIN, 1 000 ₽ @ 2.40' },
            reg: { ok: true, val: 'HOME_WIN, 100 000 коп. @ 2.40' },
            cli: { ok: true, val: 'HOME_WIN, 1 000 ₽ @ 2.40' }
        },
        {
            field: 'Токен клиента у Букмекера Alpha',
            bm: { ok: true, val: tokAlpha },
            reg: { ok: true, val: tokAlpha },
            cli: { ok: true, val: tokAlpha }
        },
        {
            field: 'Активность игрока в БК Beta (защита от сговора контор)',
            bm: { ok: false, val: '🔒 Токен P_BK_BETA не связывается' },
            reg: { ok: true, val: 'Видит оба токена в эскроу' },
            cli: { ok: true, val: 'Владеет обоими токенами' }
        },
        {
            field: 'Гражданская личность (ФИО, Паспорт 4018 123456)',
            bm: { ok: false, val: '🔒 Скрыто криптографией навсегда' },
            reg: {
                ok: isRevealed,
                val: isRevealed ? `🔓 Раскрыто (2/3): ${s.wallet.fullName}` : '🔒 Зашифровано AES-GCM (нужно 2 доли из 3)'
            },
            cli: { ok: true, val: s.wallet.fullName || 'Иванов Иван Иванович' }
        }
    ];

    const dbDump = {
        links: s.regulator.links,
        accounts: [s.accounts.client, s.accounts.bookmaker, s.accounts.house],
        holds: s.regulator.holds,
        bm_token_exposure: s.bookmaker.exposures,
        custody_shares: [
            { party: 'client (локально :5003)', share: s.wallet.clientShare },
            { party: 'regulator (БД :5001)', share: s.regulator.regulatorShare },
            { party: 'arbiter (БД :5004)', share: s.arbiter.storedShare }
        ]
    };

    const buttonsHtml = Object.keys(dbDump).map((tbl) => `
        <button onclick="setSelectedSqlTable('${tbl}')" class="px-2.5 py-1 rounded text-xs font-mono font-semibold transition cursor-pointer ${
            uiState.selectedSqlTable === tbl ? 'bg-indigo-600 text-white' : 'bg-slate-800 text-slate-400 hover:bg-slate-700'
        }">SQL: ${tbl}</button>
    `).join('');

    document.getElementById('privacy-matrix-section').innerHTML = `
        <div class="flex flex-wrap items-center justify-between gap-4 mb-4">
            <div>
                <h3 class="text-base font-bold flex items-center gap-2">🗄️ Инспектор видимости данных («Матрица Приватности») и Raw SQLite Инспектор</h3>
                <p class="text-xs text-slate-400">Наглядно показывает, что физически видит каждый сервис в своей базе данных SQLAlchemy</p>
            </div>
            <div class="flex flex-wrap gap-1.5">${buttonsHtml}</div>
        </div>

        <div class="grid grid-cols-1 xl:grid-cols-12 gap-5">
            <div class="xl:col-span-7 overflow-x-auto">
                <table class="w-full text-left text-xs border-collapse">
                    <thead>
                        <tr class="border-b border-slate-800 text-slate-400">
                            <th class="py-2 pr-3">Сущность данных</th>
                            <th class="py-2 px-2">Букмекер (:5002)</th>
                            <th class="py-2 px-2">Регулятор (:5001)</th>
                            <th class="py-2 px-2">Клиент (:5003)</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${matrixRows.map((r) => `
                            <tr class="border-b border-slate-800/60">
                                <td class="py-2.5 pr-3 font-medium">${r.field}</td>
                                <td class="py-2.5 px-2 font-mono text-[11px]">
                                    <span class="inline-flex px-2 py-0.5 rounded ${r.bm.ok ? 'bg-emerald-500/15 text-emerald-400' : 'bg-rose-500/15 text-rose-400'}">${r.bm.val}</span>
                                </td>
                                <td class="py-2.5 px-2 font-mono text-[11px]">
                                    <span class="inline-flex px-2 py-0.5 rounded ${r.reg.ok ? 'bg-emerald-500/15 text-emerald-400' : 'bg-amber-500/15 text-amber-400'}">${r.reg.val}</span>
                                </td>
                                <td class="py-2.5 px-2 font-mono text-[11px]">
                                    <span class="inline-flex px-2 py-0.5 rounded bg-emerald-500/15 text-emerald-400">${r.cli.val}</span>
                                </td>
                            </tr>
                        `).join('')}
                    </tbody>
                </table>
            </div>

            <div class="xl:col-span-5 rounded-xl border p-3.5 font-mono text-xs flex flex-col bg-slate-950 border-slate-800 text-slate-100">
                <div class="flex items-center justify-between text-[11px] text-slate-400 pb-2 mb-2 border-b border-slate-800">
                    <span class="text-indigo-400 font-bold">&gt;_ SELECT * FROM ${uiState.selectedSqlTable};</span>
                    <span>SQLAlchemy ORM Inspector</span>
                </div>
                <pre class="overflow-x-auto text-[11px] leading-relaxed text-emerald-300 flex-1 max-h-56">${JSON.stringify(dbDump[uiState.selectedSqlTable], null, 2)}</pre>
            </div>
        </div>
    `;
}

function renderAuditLog() {
    const reg = uiState.serverData.regulator;
    document.getElementById('header-audit-root').textContent = `0x${reg.auditRoot.slice(0, 16)}…`;

    const rowsHtml = reg.auditLogs.length === 0
        ? `<tr><td colspan="6" class="py-3 text-center text-slate-500 italic">Журнал аудита пуст — выполните Шаг 1</td></tr>`
        : reg.auditLogs.map((log) => `
            <tr class="border-b border-slate-800/50">
                <td class="py-2 px-2 font-bold text-emerald-400">#${log.seq}</td>
                <td class="py-2 px-2 text-slate-400">${log.ts}</td>
                <td class="py-2 px-2"><span class="px-2 py-0.5 rounded bg-slate-800 text-slate-200">${log.actor}</span></td>
                <td class="py-2 px-2 font-bold text-indigo-400">${log.action}</td>
                <td class="py-2 px-2 text-slate-500">0x${log.prev_hash.slice(0, 14)}…</td>
                <td class="py-2 px-2 text-emerald-400 font-semibold">0x${log.current_hash.slice(0, 16)}…</td>
            </tr>
        `).join('');

    document.getElementById('audit-log-section').innerHTML = `
        <div class="flex flex-wrap items-center justify-between gap-2 mb-3">
            <div>
                <h3 class="text-sm font-bold uppercase tracking-wider">🔗 Неперезаписываемый Журнал Аудита (SHA-256 Hash-Chain)</h3>
                <p class="text-xs text-slate-400">Каждая запись включает хэш предыдущей: подделать историю ставок или скрыть факт деанонимизации невозможно</p>
            </div>
            <div class="text-xs font-mono px-3 py-1 rounded-lg bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
                Root Hash: 0x${reg.auditRoot.slice(0, 20)}…
            </div>
        </div>
        <div class="overflow-x-auto">
            <table class="w-full text-left text-xs font-mono">
                <thead>
                    <tr class="border-b border-slate-800 text-slate-400">
                        <th class="py-2 px-2">Seq</th>
                        <th class="py-2 px-2">Время</th>
                        <th class="py-2 px-2">Актор</th>
                        <th class="py-2 px-2">Действие</th>
                        <th class="py-2 px-2">Prev Hash (SHA-256)</th>
                        <th class="py-2 px-2">Current Hash (SHA-256)</th>
                    </tr>
                </thead>
                <tbody>${rowsHtml}</tbody>
            </table>
        </div>
    `;
}

function renderGridVisibility() {
    const grid = document.getElementById('services-grid');
    const panels = {
        client: document.getElementById('panel-client'),
        bookmaker: document.getElementById('panel-bookmaker'),
        regulator: document.getElementById('panel-regulator'),
        arbiter: document.getElementById('panel-arbiter')
    };

    if (uiState.viewTab === 'split') {
        grid.className = 'grid grid-cols-1 lg:grid-cols-2 gap-5';
        Object.values(panels).forEach((p) => p.classList.remove('hidden'));
    } else {
        grid.className = 'grid grid-cols-1 gap-5';
        Object.entries(panels).forEach(([key, p]) => {
            if (key === uiState.viewTab) p.classList.remove('hidden');
            else p.classList.add('hidden');
        });
    }
}

function renderAll() {
    if (!uiState.serverData) return;
    renderStepper();
    renderBanners();
    renderEscrowVisualizer();
    renderClientPanel();
    renderBookmakerPanel();
    renderRegulatorPanel();
    renderArbiterPanel();
    renderGridVisibility();
    renderPrivacyMatrix();
    renderAuditLog();
}

window.addEventListener('DOMContentLoaded', () => {
    syncState();
});
