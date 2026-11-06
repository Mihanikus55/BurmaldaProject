let appState = null;
let currentCase = 1;
let isDbOpen = false;
let activeDbTab = 'links';

function fmtRub(kopecks) {
    const num = Number(kopecks || 0);
    return (num / 100).toLocaleString('ru-RU') + ' ₽';
}

function setStatus(msg, code = 'HTTP 200') {
    document.getElementById('status-message').innerText = msg;
    document.getElementById('status-code').innerText = code;
}

function highlightNodes(nodeIds) {
    ['node-client', 'node-bookmaker', 'node-regulator', 'node-arbiter'].forEach(id => {
        const el = document.getElementById(id);
        if (nodeIds.includes(id)) {
            el.classList.add('node-active');
        } else {
            el.classList.remove('node-active');
        }
    });
}

function switchCaseMode(caseNum) {
    currentCase = caseNum;
    const p1 = document.getElementById('panel-case-1');
    const p2 = document.getElementById('panel-case-2');
    const t1 = document.getElementById('tab-case-1');
    const t2 = document.getElementById('tab-case-2');

    if (caseNum === 1) {
        p1.classList.remove('hidden');
        p2.classList.add('hidden');
        t1.className = 'px-3 py-1.5 rounded-md font-semibold bg-slate-800 text-white transition cursor-pointer';
        t2.className = 'px-3 py-1.5 rounded-md font-semibold text-slate-400 hover:text-slate-200 transition cursor-pointer';
    } else {
        p1.classList.add('hidden');
        p2.classList.remove('hidden');
        t2.className = 'px-3 py-1.5 rounded-md font-semibold bg-slate-800 text-white transition cursor-pointer';
        t1.className = 'px-3 py-1.5 rounded-md font-semibold text-slate-400 hover:text-slate-200 transition cursor-pointer';
    }
}

function toggleDbInspector() {
    isDbOpen = !isDbOpen;
    const panel = document.getElementById('db-inspector-panel');
    const badge = document.getElementById('db-badge');
    if (isDbOpen) {
        panel.classList.remove('hidden');
        badge.innerText = 'ОТКРЫТ';
        badge.className = 'px-1.5 py-0.5 rounded bg-emerald-500/20 text-emerald-300 font-mono text-[10px]';
        if (appState) renderDbTable(appState);
    } else {
        panel.classList.add('hidden');
        badge.innerText = 'СКРЫТ';
        badge.className = 'px-1.5 py-0.5 rounded bg-slate-900 text-slate-400 font-mono text-[10px]';
    }
}

function switchDbTab(tabName) {
    activeDbTab = tabName;
    ['links', 'holds', 'accounts', 'bm_token_exposure', 'ledger', 'audit_log'].forEach(t => {
        const btn = document.getElementById(`dbtab-${t}`);
        if (btn) {
            btn.className = (t === tabName)
                ? 'px-3 py-1.5 rounded bg-slate-200 text-slate-900 font-bold cursor-pointer'
                : 'px-3 py-1.5 rounded bg-[#0D1117] text-slate-400 border border-slate-800 cursor-pointer';
        }
    });
    if (appState) renderDbTable(appState);
}

async function fetchState() {
    const res = await fetch('/api/state');
    appState = await res.json();
    renderUI(appState);
}

// =============================================================================
// КЕЙС 1: ОДИНОЧНАЯ СТАВКА И ПОШАГОВЫЙ ПРОЦЕСС
// =============================================================================
async function runCase1Bet() {
    document.getElementById('disclosure-banner').classList.add('hidden');
    document.getElementById('flow-indicator').innerText = 'Клиент → Регулятор (KYC + AES-GCM) → Букмекер → Эскроу (Холд)';
    highlightNodes(['node-client', 'node-bookmaker', 'node-regulator']);

    if (!appState || !appState.wallet.registered) {
        await fetch('/api/client/v1/register-full', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ full_name: 'Иванов Иван Иванович', passport: '4018 123456', age: 23 })
        });
    }
    await fetchState();
    if (appState.accounts.client.available < 100000) {
        await fetch('/api/demo/deposit-both', { method: 'POST' });
    }
    const betRes = await fetch('/api/client/v1/place-bet', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ selection: 'HOME_WIN', stake: 100000, event_id: 'ev_final_2026' })
    });
    const betData = await betRes.json();
    setStatus(`Ставка ${betData.bet_id} принята под токеном ${betData.token}. В эскроу заморожено: 1 000 ₽ клиента + 1 400 ₽ риска БК.`, 'HTTP 201');
    await fetchState();
}

async function runCase1Settle() {
    document.getElementById('flow-indicator').innerText = 'Регулятор (Эскроу) → Распределение холдов → Клиент (+2 400 ₽)';
    highlightNodes(['node-regulator', 'node-client']);
    const res = await fetch('/api/regulator/v1/events/ev_final_2026/outcome', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ outcome: 'HOME_WIN' })
    });
    const d = await res.json();
    setStatus(`Матч рассчитан (HOME_WIN). Рассчитано ставок: ${d.settled_bets.length}. Выигрыш переведён из эскроу.`, 'HTTP 200');
    await fetchState();
}

async function runCase1DisclosureTest() {
    highlightNodes(['node-regulator', 'node-arbiter']);
    const res = await fetch('/api/regulator/v1/disclosures/solo-attempt', { method: 'POST' });
    const d = await res.json();
    const banner = document.getElementById('disclosure-banner');
    document.getElementById('disclosure-text').innerText = d.message;
    document.getElementById('btn-arbiter-approve').classList.remove('hidden');
    banner.classList.remove('hidden');
    setStatus(d.message, 'HTTP 403 FORBIDDEN');
    await fetchState();
}

async function approveArbiterDisclosure() {
    const res = await fetch('/api/arbiter/v1/disclosures/approve', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ reason: 'Судебный ордер №42' })
    });
    await res.json();
    document.getElementById('btn-arbiter-approve').classList.add('hidden');
    setStatus('Порог Шамира «2 из 3» собран (Регулятор + Арбитр). Ключ AES-256-GCM восстановлен интерполяцией Лагранжа.', 'HTTP 200');
    await fetchState();
}

// =============================================================================
// КЕЙС 2: МАССОВАЯ НАГРУЗКА (10 ИГРОКОВ И СТАВОК)
// =============================================================================
async function runCase2Mass10() {
    setStatus('Генерация 10 профилей (AES-256-GCM + Шамир) и 10 ставок...', 'PROCESSING');
    const res = await fetch('/api/regulator/v1/demo/mass-10', { method: 'POST' });
    const d = await res.json();
    setStatus(`Сгенерировано ${d.players_count} игроков и 10 ставок. Откройте «🗄️ БД / Инспектор» для просмотра таблиц.`, 'HTTP 201');
    if (!isDbOpen) toggleDbInspector();
    await fetchState();
}

// =============================================================================
// 3 СЦЕНАРИЯ SMPC
// =============================================================================
async function runSmpcAntifraud() {
    highlightNodes(['node-bookmaker', 'node-regulator', 'node-arbiter']);
    const res = await fetch('/api/regulator/v1/smpc/antifraud', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ score_alpha: 68, score_beta: 54, threshold: 100 })
    });
    const d = await res.json();
    setStatus(`[${d.protocol}] Доля Alpha: ${d.bk_alpha_share_node1} | Доля Beta: ${d.bk_beta_share_node1} → Сумма скоров = ${d.combined_score} (Порог ${d.threshold}) → ${d.verdict}`, 'SMPC 200');
    await fetchState();
}

async function runSmpcSolvency() {
    highlightNodes(['node-bookmaker', 'node-regulator']);
    const res = await fetch('/api/regulator/v1/smpc/solvency', { method: 'POST' });
    const d = await res.json();
    setStatus(`[${d.protocol}] Заслеплённая разность узла #1: ${d.node_1_blinded_diff} → Коэффициент покрытия: ${d.coverage_ratio}x → ${d.verdict}`, 'SMPC 200');
    await fetchState();
}

async function runSmpcOracleSettle() {
    highlightNodes(['node-regulator', 'node-arbiter', 'node-client']);
    const res = await fetch('/api/regulator/v1/smpc/oracle-settle', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ votes: ['HOME_WIN', 'HOME_WIN', 'AWAY_WIN'] })
    });
    const d = await res.json();
    setStatus(`[${d.protocol}] Консенсус 3 оракулов достигнут (${d.votes_for_winner}/3 за ${d.outcome}). Автоматически рассчитано ставок: ${d.settled_bets_count}.`, 'SMPC 200');
    await fetchState();
}

async function resetAll() {
    await fetch('/api/demo/reset', { method: 'POST' });
    document.getElementById('disclosure-banner').classList.add('hidden');
    highlightNodes([]);
    setStatus('База данных очищена.', 'HTTP 200');
    await fetchState();
}

// =============================================================================
// ОТРИСОВКА UI И ТАБЛИЦ БАЗЫ ДАННЫХ
// =============================================================================
function renderUI(st) {
    document.getElementById('hdr-audit-root').innerText = '0x' + (st.regulator.audit_root || '').slice(0, 20) + '...';

    document.getElementById('ui-clients-count').innerText = `${st.summary.clients_count} профилей`;
    const cliAvail = st.summary.clients_count > 1 ? st.summary.total_clients_available : st.accounts.client.available;
    const cliHeld = st.summary.clients_count > 1 ? st.summary.total_clients_held : st.accounts.client.held;

    document.getElementById('ui-cli-avail').innerText = fmtRub(cliAvail);
    document.getElementById('ui-cli-held').innerText = fmtRub(cliHeld);
    document.getElementById('ui-tok-a').innerText = st.wallet.tokens.bk_alpha || '—';
    document.getElementById('ui-tok-b').innerText = st.wallet.tokens.bk_beta || '—';
    document.getElementById('ui-share-1').innerText = st.wallet.client_share || '—';

    document.getElementById('ui-bk-avail').innerText = fmtRub(st.accounts.bookmaker.available);
    document.getElementById('ui-bk-held').innerText = fmtRub(st.accounts.bookmaker.held);
    document.getElementById('ui-bets-count').innerText = st.summary.bets_count;

    const totalEscrow = cliHeld + (st.accounts.bookmaker.held || 0);
    document.getElementById('ui-total-escrow').innerText = fmtRub(totalEscrow);
    document.getElementById('ui-links-count').innerText = st.regulator.links.length;
    document.getElementById('ui-ev-status').innerText = st.regulator.event_status;
    document.getElementById('ui-share-2').innerText = st.regulator.regulator_share || '—';
    document.getElementById('ui-share-3').innerText = st.arbiter.stored_share || '—';

    if (st.disclosure && st.disclosure.status === 'REVEALED' && st.disclosure.revealed_identity) {
        const p = st.disclosure.revealed_identity;
        document.getElementById('ui-disc-status').innerText = `РАСКРЫТО (${st.disclosure.collected.join('+')})`;
        document.getElementById('ui-revealed-name').innerText = `${p.full_name} (${p.passport})`;
        document.getElementById('disclosure-text').innerText =
            `Расшифровано AES-256-GCM (доли ${st.disclosure.collected.join(' + ')}): ${p.full_name}, паспорт ${p.passport}, ID ${p.client_id}`;
    } else {
        document.getElementById('ui-disc-status').innerText = 'ЗАЩИЩЕНО';
        document.getElementById('ui-revealed-name').innerText = 'ФИО скрыто';
    }

    if (isDbOpen) {
        renderDbTable(st);
    }
}

function renderDbTable(st) {
    const thead = document.getElementById('db-table-head');
    const tbody = document.getElementById('db-table-body');

    if (activeDbTab === 'links') {
        thead.innerHTML = '<tr><th class="p-2">token (PK)</th><th class="p-2">bookmaker_id</th><th class="p-2">client_ref_sealed (AES-256-GCM)</th></tr>';
        tbody.innerHTML = st.regulator.links.map(r => `
            <tr>
                <td class="p-2 text-slate-200 font-bold">${r.token}</td>
                <td class="p-2 text-slate-400">${r.bookmaker_id}</td>
                <td class="p-2 text-slate-400 truncate max-w-lg">${r.client_ref_sealed}</td>
            </tr>
        `).join('') || '<tr><td colspan="3" class="p-3 text-slate-500">Пусто</td></tr>';
    } else if (activeDbTab === 'holds') {
        thead.innerHTML = '<tr><th class="p-2">hold_id</th><th class="p-2">owner_ref</th><th class="p-2">ref_type</th><th class="p-2">amount (коп.)</th><th class="p-2">status</th></tr>';
        tbody.innerHTML = st.regulator.holds.map(h => `
            <tr>
                <td class="p-2 text-slate-300">${h.id}</td>
                <td class="p-2 text-slate-300">${h.owner_ref}</td>
                <td class="p-2 text-slate-400">${h.ref_type}</td>
                <td class="p-2 text-slate-200 font-bold">${h.amount.toLocaleString('ru-RU')} (${fmtRub(h.amount)})</td>
                <td class="p-2 text-slate-300">${h.status}</td>
            </tr>
        `).join('') || '<tr><td colspan="5" class="p-3 text-slate-500">Пусто</td></tr>';
    } else if (activeDbTab === 'accounts') {
        thead.innerHTML = '<tr><th class="p-2">owner_ref</th><th class="p-2">available (коп.)</th><th class="p-2">held (коп.)</th><th class="p-2">version</th></tr>';
        tbody.innerHTML = st.accounts.all.map(a => `
            <tr>
                <td class="p-2 text-slate-200 font-bold">${a.owner_ref}</td>
                <td class="p-2 text-emerald-400">${a.available.toLocaleString('ru-RU')} (${fmtRub(a.available)})</td>
                <td class="p-2 text-slate-300">${a.held.toLocaleString('ru-RU')} (${fmtRub(a.held)})</td>
                <td class="p-2 text-slate-500">v${a.version}</td>
            </tr>
        `).join('');
    } else if (activeDbTab === 'bm_token_exposure') {
        thead.innerHTML = '<tr><th class="p-2">token (Псевдоним в БК)</th><th class="p-2">bets_count</th><th class="p-2">total_staked</th><th class="p-2">won_count</th><th class="p-2">ФИО</th></tr>';
        tbody.innerHTML = st.bookmaker.exposures.map(x => `
            <tr>
                <td class="p-2 text-slate-200 font-bold">${x.token}</td>
                <td class="p-2 text-slate-300">${x.bets_count}</td>
                <td class="p-2 text-slate-300">${fmtRub(x.total_staked)}</td>
                <td class="p-2 text-emerald-400">${x.won_count}</td>
                <td class="p-2 text-slate-500">🔒 ОТСУТСТВУЕТ</td>
            </tr>
        `).join('') || '<tr><td colspan="5" class="p-3 text-slate-500">Пусто</td></tr>';
    } else if (activeDbTab === 'ledger') {
        thead.innerHTML = '<tr><th class="p-2">tx_id</th><th class="p-2">account_id</th><th class="p-2">direction</th><th class="p-2">amount (коп.)</th></tr>';
        tbody.innerHTML = st.regulator.ledger.map(e => `
            <tr>
                <td class="p-2 text-slate-400">${e.tx_id}</td>
                <td class="p-2 text-slate-300">${e.account_id}</td>
                <td class="p-2 ${e.direction === 'CREDIT' ? 'text-emerald-400' : 'text-rose-400'} font-bold">${e.direction}</td>
                <td class="p-2 text-slate-200">${e.amount.toLocaleString('ru-RU')} (${fmtRub(e.amount)})</td>
            </tr>
        `).join('') || '<tr><td colspan="4" class="p-3 text-slate-500">Пусто</td></tr>';
    } else if (activeDbTab === 'audit_log') {
        thead.innerHTML = '<tr><th class="p-2">seq</th><th class="p-2">ts</th><th class="p-2">actor</th><th class="p-2">action</th><th class="p-2">prev_hash</th><th class="p-2">current_hash</th></tr>';
        tbody.innerHTML = st.regulator.audit_logs.map(l => `
            <tr>
                <td class="p-2 text-slate-300">#${l.seq}</td>
                <td class="p-2 text-slate-500">${l.ts}</td>
                <td class="p-2 text-slate-300">${l.actor}</td>
                <td class="p-2 text-slate-200 font-bold">${l.action}</td>
                <td class="p-2 text-slate-500">0x${l.prev_hash.slice(0, 14)}...</td>
                <td class="p-2 text-emerald-400">0x${l.current_hash.slice(0, 16)}...</td>
            </tr>
        `).join('') || '<tr><td colspan="6" class="p-3 text-slate-500">Пусто</td></tr>';
    }
}

window.addEventListener('DOMContentLoaded', () => {
    fetchState();
});
