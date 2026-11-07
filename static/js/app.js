"use strict";

const $ = (selector) => document.querySelector(selector);
const escapeHtml = (value) => String(value ?? "").replace(/[&<>"']/g, (c) => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const short = (value, size = 14) => escapeHtml(String(value || "—").length > size ? String(value).slice(0, size) + "…" : value || "—");
const money = (value) => new Intl.NumberFormat("ru-RU", {style:"currency", currency:"RUB", maximumFractionDigits:2}).format((value || 0) / 100);
const uid = () => crypto.randomUUID();
const fieldNames = {full_name:"ФИО", passport:"Документ", age:"Возраст"};
const titles = {wallet:"Клиент", cupis:"ЦУПИС", bookmaker_alpha:"Букмекер Alpha", bookmaker_beta:"Букмекер Beta", arbiter:"Арбитр", recipient:"Получатель", disclosure:"Раскрытие"};
const icons = {
  wallet:'<circle cx="12" cy="8" r="3.5"/><path d="M5 21v-3a7 7 0 0 1 14 0v3"/>',
  cupis:'<path d="m3 8 9-5 9 5M4 9h16M5 19h14M3 22h18M6 10v7m6-7v7m6-7v7"/>',
  bookmaker_alpha:'<rect x="4" y="6" width="16" height="15" rx="3"/><path d="M9 6V3h6v3M8 12h8m-8 4h5"/>',
  bookmaker_beta:'<rect x="4" y="6" width="16" height="15" rx="3"/><path d="M9 6V3h6v3M8 12h8m-8 4h5"/>',
  arbiter:'<path d="M12 3v18M5 21h14M4 7h16M6 7l-4 8h8L6 7Zm12 0-4 8h8l-4-8Z"/>',
  recipient:'<path d="M6 3h9l4 4v14H6zM14 3v5h5M9 12h7m-7 4h5"/>',
  disclosure:'<rect x="5" y="10" width="14" height="11" rx="3"/><path d="M8 10V7a4 4 0 0 1 8 0v3M12 14v3"/>'
};
const icon = (role) => `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${icons[role] || icons.disclosure}</svg>`;
const steps = [
  ["Регистрация", "Шифрование и три доли"], ["Приватная ставка", "История по псевдониму"],
  ["Проверка утечки", "База + одна доля"], ["Запрос раскрытия", "Адресат, цель и поля"],
  ["Подтверждение", "Две доли из трёх"], ["Передача и ротация", "Новый ключ и новые доли"]
];
let snapshot = null, page = "scenario", selectedRole = "bookmaker_alpha", selectedClient = "", viewStep = null, busy = false;
let toastTimer;
const draft = {bookmaker:"bookmaker_alpha", event_id:"cup-final", selection:"HOME_WIN", stake:"1000", reason:"Проверка обращения игрока", fields:["full_name","age"]};

function role(name) { return snapshot?.roles?.[name] || {}; }
function clients() { return role("wallet").clients || []; }
function client() { return clients().find(c => c.client_id === selectedClient) || clients()[0]; }
function cupisClient() { return (role("cupis").clients || []).find(c => c.client_id === client()?.client_id); }
function requests() { return (role("disclosure").requests || []).filter(r => r.request.client_id === client()?.client_id); }
function latestRequest() { return requests().at(-1); }
function ownBets() {
  const aliases = client()?.pseudonyms || {};
  return ["bookmaker_alpha","bookmaker_beta"].flatMap(book => (role(book).bets || []).filter(b => b.quote.pseudonym === aliases[book]));
}
function progress() {
  if (!client()) return 0;
  if (!ownBets().length) return 1;
  if (!snapshot.probes?.[client().client_id]) return 2;
  const last = latestRequest();
  if (!last || last.status === "DENIED") return 3;
  return last.status === "COMPLETED" ? 5 : 4;
}
function tag(text, type = "") { return `<span class="tag ${type}">${escapeHtml(text)}</span>`; }
function button(text, action, type="primary", extra="") { return `<button class="button ${type}" data-action="${action}" ${busy?"disabled":""} ${extra}>${escapeHtml(text)}</button>`; }
function toast(text, error=false) {
  const box = $("#toast"); box.textContent = text; box.className = "toast" + (error?" error":""); box.hidden = false;
  clearTimeout(toastTimer); toastTimer = setTimeout(() => {box.hidden=true;}, 6500);
}
const errors = {INVALID_AMOUNT:"Введите положительную сумму в допустимом диапазоне.",INSUFFICIENT_FUNDS:"На условном счёте недостаточно средств.",ADMISSION_REVOKED:"Допуск отозван. Новая ставка отклонена.",EVENT_CLOSED:"Это событие уже рассчитано. Выберите другое событие или букмекера.",DISCLOSURE_ALREADY_PENDING:"У клиента уже есть незавершённый запрос раскрытия.",REQUEST_NOT_PENDING_OR_EXPIRED:"Запрос отклонён, завершён или истёк. Создайте новый.",PEER_UNAVAILABLE:"Один из участников недоступен. Сохранённую доставку можно продолжить.",UNDERAGE:"Демонстрационный допуск выдаётся только совершеннолетним.",INVALID_IDENTITY:"Проверьте вымышленные данные клиента.",QUOTE_EXPIRED_OR_CHANGED:"Котировка истекла или изменилась. Повторите запрос.",INVALID_INPUT:"Проверьте заполненные поля.",INTERNAL_ERROR:"Операция не завершена. Проверьте состояние участников и повторите безопасное продолжение."};
async function load() {
  const res = await fetch("/api/state");
  if (!res.ok) throw new Error("Не удалось получить состояние. Обновите страницу.");
  snapshot = await res.json();
  if (!clients().some(c => c.client_id === selectedClient)) selectedClient = clients()[0]?.client_id || "";
  render();
}
async function act(action, body, success) {
  if (busy) return;
  busy=true; render();
  try {
    const res = await fetch(`/api/actions/${action}`, {method:"POST", headers:{"Content-Type":"application/json", "X-Demo-CSRF":$("meta[name=demo-csrf]").content}, body:JSON.stringify(body)});
    const result = await res.json();
    if (!res.ok) throw new Error(errors[result.error] || result.error || "Операция отклонена");
    if (action === "enroll") selectedClient = result.client_id;
    viewStep = null;
    toast(success || "Операция выполнена");
    return result;
  } catch (err) { toast(err.message, true); }
  finally { busy=false; await load().catch(err => toast(err.message, true)); }
}
function chooseClient() {
  if (!client()) return "";
  return `<div class="selected-client"><div class="avatar">${escapeHtml(client().identity.full_name.slice(0,1))}</div><div><strong>Синтетический игрок</strong><small>Данные из клиентского кошелька</small></div><select id="client-picker" aria-label="Выбрать клиента">${clients().map(c => `<option value="${escapeHtml(c.client_id)}" ${c.client_id===client().client_id?"selected":""}>${escapeHtml(c.identity.full_name)}</option>`).join("")}</select></div>`;
}
function bookSelect(id="book-picker") {
  return `<select id="${id}" data-draft="bookmaker" aria-label="Букмекер"><option value="bookmaker_alpha" ${draft.bookmaker==="bookmaker_alpha"?"selected":""}>Alpha</option><option value="bookmaker_beta" ${draft.bookmaker==="bookmaker_beta"?"selected":""}>Beta</option></select>`;
}
function shareStrip() {
  return `<div class="share-strip">${[["wallet","Клиент"],["cupis","ЦУПИС"],["arbiter","Арбитр"]].map(([r,n],i) => {const part=(role(r).shares || []).find(s => s.client_id===client()?.client_id);return `<div class="share-tile"><span class="share-index">0${i+1}</span><strong>${n}</strong><span>${part?`Доля сохранена · v${part.version}`:"Ещё не создана"}</span></div>`;}).join("")}</div>`;
}
function flow() {
  const completed = latestRequest()?.status === "COMPLETED";
  const entries = [["wallet","Клиент","Собственные данные","Доля 1 / 3"],["cupis","ЦУПИС","Зашифрованный архив","Доля 2 / 3"],["bookmaker_alpha","Букмекер","Ставки по псевдониму","Без документов"],["arbiter","Арбитр","Независимое одобрение","Доля 3 / 3"],["recipient","Получатель","Только разрешённые поля",completed?"Данные доставлены":"Личность закрыта"]];
  return `<section class="panel flow-panel"><div class="panel-head"><div><h2 class="panel-title">Одна система. Разные границы доступа.</h2><p class="panel-subtitle">Выберите участника, чтобы увидеть его данные</p></div>${tag("Шамир · 2 из 3","purple")}</div><div class="flow-track">${entries.map(([r,n,d,t]) => `<button class="actor ${selectedRole===r?"selected":""}" data-role="${r}" aria-label="Посмотреть данные: ${n}"><span class="actor-icon">${icon(r)}</span><span class="actor-name">${n}</span><span class="actor-desc">${d}</span>${tag(t,r==="bookmaker_alpha"?"green":completed&&r==="recipient"?"green":"")}</button>`).join("")}</div><div class="flow-foot"><span><b>AES-256-GCM</b> · документы</span><span><b>Ed25519</b> · подписи</span><span><b>Отдельные базы</b> · отдельные ключи</span></div></section>`;
}
function journey(step) {
  const current = progress();
  return `<section class="panel journey"><div class="journey-head"><h2>Сценарий демонстрации</h2><span class="progress-label">${Math.min(current+1,6)} / 6</span></div><div class="steps-list">${steps.map(([name,desc],i) => `<button class="step ${i===step?"active":i<current?"done":""}" data-step="${i}" ${!client()&&i>0?"disabled":""}><span class="step-number">${i<current?"✓":i+1}</span><span><span class="step-title">${name}</span><span class="step-desc">${desc}</span></span></button>`).join("")}</div><div class="journey-note">Каждый шаг меняет реальные записи локального стенда. Подписи, шифрование и проверки выполняются на сервере.</div></section>`;
}
function detail(step) {
  const c = client(), cp = cupisClient(), req = latestRequest();
  const heads = ["Начнём с защищённого архива","Букмекер видит псевдоним","Одной доли недостаточно","Раскрытие — только по запросу","Решение остаётся за хранителем","Данные переданы. Ключ обновлён."];
  let content = "";
  if (step===0) {
    content = `<p class="detail-copy">Создадим вымышленного игрока. Документы зашифруются индивидуальным ключом, а ключ разделится между тремя независимыми хранителями.</p>${c?chooseClient():""}<div class="share-strip"><div class="share-tile"><span class="share-index">256</span><strong>бит ключа AES</strong><span>Отдельный для клиента</span></div><div class="share-tile"><span class="share-index">2 / 3</span><strong>Порог восстановления</strong><span>Одна доля не открывает архив</span></div><div class="share-tile"><span class="share-index">3</span><strong>Разных хранилища</strong><span>Клиент · ЦУПИС · арбитр</span></div></div><div class="privacy-note"><span>◈</span><div>ЦУПИС видит документы при идентификации. После сохранения в его архиве остаются <strong>шифротекст и одна доля</strong>.</div></div><div class="button-row">${button(c?"Добавить ещё игрока":"Создать демо-игрока →","enroll-modal")}${c?button("Продолжить к ставке →","go-bet","secondary"):""}</div><div class="supporting-note">Только вымышленные данные. Стенд не выполняет настоящую KYC-проверку.</div>`;
  } else if (step===1 && c) {
    content = `${chooseClient()}<p class="detail-copy">Alpha и Beta получают разные постоянные псевдонимы. Ни ФИО, ни документ, ни доли ключа не входят в сообщение букмекеру.</p><div class="field-row"><label><span class="field-label">Букмекер</span>${bookSelect()}</label><label><span class="field-label">Условная сумма, ₽</span><input id="stake" data-draft="stake" type="number" min="1" max="1000000" step="0.01" value="${escapeHtml(draft.stake)}"></label></div><div class="field-row"><label><span class="field-label">Событие</span><select data-draft="event_id" id="event-picker"><option value="cup-final" ${draft.event_id==="cup-final"?"selected":""}>Финал кубка · Север — Юг</option><option value="league-match" ${draft.event_id==="league-match"?"selected":""}>Матч лиги · Восток — Запад</option></select></label><label><span class="field-label">Исход</span><select data-draft="selection" id="selection-picker"><option value="HOME_WIN" ${draft.selection==="HOME_WIN"?"selected":""}>Победа хозяев · 2.40</option><option value="AWAY_WIN" ${draft.selection==="AWAY_WIN"?"selected":""}>Победа гостей · 1.65</option></select></label></div><div class="code-box"><div class="code-label">СООБЩЕНИЕ БУКМЕКЕРУ</div>pseudonym: <span class="code-purple">${short(c.pseudonyms[draft.bookmaker],32)}</span><br>event_id: ${escapeHtml(draft.event_id)}<br>stake: ${escapeHtml(draft.stake)} ₽<br>identity: <span class="code-green">не передаётся</span></div><div class="button-row">${button("Подтвердить ставку →","bet")}${button("Рассчитать событие","settle-modal","secondary")}</div><div class="metrics-line"><div class="metric"><strong>${money(cp?.account?.available)}</strong><span>Доступно на демо-счёте</span></div><div class="metric"><strong>${ownBets().length}</strong><span>Ставок этого игрока</span></div><div class="metric"><strong>${cp?.eligible?"Активен":"Отозван"}</strong><span>Допуск</span></div></div>`;
  } else if (step===2 && c) {
    const probe = snapshot.probes?.[c.client_id];
    content = `${chooseClient()}<p class="detail-copy">Моделируем доступ к шифротексту и собственной доле ЦУПИС. Проверяем порог восстановления, не запрашивая долю клиента или арбитра.</p>${shareStrip()}<div class="code-box"><div class="code-label">ЗАЩИЩЁННАЯ ЗАПИСЬ · v${cp?.archive?.version || 1}</div>algorithm: <span class="code-green">AES-256-GCM</span><br>ciphertext: ${short(cp?.archive?.sealed?.ciphertext,70)}<br>available_shares: <span class="code-purple">1 из 3</span></div>${probe?`<div class="result-box blocked"><strong>✓ Расшифрование заблокировано</strong><p>Сервер вернул INSUFFICIENT_SHARES: доступна одна доля, требуется две. Проверка выполнена для версии v${probe.version}.</p></div>`:""}<div class="button-row">${button(probe?"Повторить проверку":"Проверить одну долю →","probe")}${probe?button("Создать запрос →","go-request","secondary"):""}</div>`;
  } else if (step===3 && c) {
    content = `${chooseClient()}<p class="detail-copy">Укажем адресата и минимальный состав данных. Подтверждение будет привязано именно к этому запросу и версии ключа.</p><div class="field-row"><label><span class="field-label">Контекст букмекера</span>${bookSelect("report-book")}</label><label><span class="field-label">Получатель</span><input value="Уполномоченный получатель (симулятор)" readonly></label></div><label><span class="field-label">Цель передачи</span><input id="reason" data-draft="reason" maxlength="300" value="${escapeHtml(draft.reason)}"></label><span class="field-label wide-gap">Какие поля разрешить</span><div class="check-fields">${Object.entries(fieldNames).map(([key,title]) => `<label class="check-field"><input type="checkbox" name="identity-field" value="${key}" ${draft.fields.includes(key)?"checked":""}>${title}</label>`).join("")}</div><div class="privacy-note"><span>◎</span><div>Остальные поля останутся закрыты. Букмекер <strong>не является адресатом</strong> раскрытия.</div></div><div class="button-row">${button("Создать запрос →","request")}</div>`;
  } else if (step===4 && c) {
    content = `${chooseClient()}<p class="detail-copy">Клиент может подтвердить передачу в своём приложении. Для исключительного сценария независимый арбитр может одобрить запрос или отказать.</p>${req?requestCard(req,true):'<div class="empty">Сначала создайте запрос раскрытия.</div>'}${shareStrip()}<div class="supporting-note">Доли передаются зашифрованно компоненту раскрытия. Сырые доли и полный ключ не отображаются в этой панели.</div>`;
  } else if (step===5 && c) {
    const records = (role("recipient").identity_reports || []).filter(r => r.body.pseudonym === c.pseudonyms[r.body.bookmaker]);
    const record = records.at(-1)?.body;
    content = `${chooseClient()}<p class="detail-copy">Получатель получил только одобренные поля. Архив клиента защищён новым ключом, а каждому хранителю доставлена новая доля.</p>${record?`<div class="result-box"><strong>✓ Доставка подтверждена получателем</strong>${Object.entries(record.identity).map(([k,v])=>`<div class="result-datum"><span>${fieldNames[k]}</span><b>${escapeHtml(v)}</b></div>`).join("")}</div>`:'<div class="empty">Пока нет завершённой передачи. Пройдите шаг подтверждения.</div>'}${shareStrip()}<div class="metrics-line"><div class="metric"><strong>v${cp?.archive?.version || 1}</strong><span>Текущий ключ</span></div><div class="metric"><strong>${req?.old_key_rejected?"Отклонён":"—"}</strong><span>Старый ключ для новой записи</span></div><div class="metric"><strong>${record?.fields.length || 0}</strong><span>Переданных полей</span></div></div><div class="button-row">${button("Посмотреть видимость →","go-visibility")}${button("Новый запрос","go-request","secondary")}</div><div class="supporting-note">Ротация не отзывает уже переданные данные и не защищает сохранённые старые копии при наличии старого ключа.</div>`;
  }
  return `<section class="panel detail"><div class="panel-head"><h2 class="panel-title">${step===5?"Результат сценария":"Рабочая область"}</h2>${tag(busy?"Выполняется…":`Шаг ${step+1} из 6`,busy?"amber":"")}</div><div class="detail-body"><div class="section-kicker">${step===5?"КОНТРОЛИРУЕМОЕ РАСКРЫТИЕ":"ПОШАГОВАЯ ДЕМОНСТРАЦИЯ"}</div><h3 class="detail-title">${heads[step]}</h3>${content}</div></section>`;
}
function requestCard(item, controls=false) {
  const r=item.request;
  const statuses={PENDING:["Ожидает подтверждения","amber"],DENIED:["Арбитр отказал","red"],ROTATING:["Доставка / ротация","purple"],COMPLETED:["Завершён","green"]};
  const [text,color]=statuses[item.status]||[item.status,""];
  return `<div class="request-card"><div class="mini-row"><div><strong>Запрос ${short(r.id,10)}</strong><small>Версия ключа v${r.version} · ${titles[r.bookmaker]}</small></div>${tag(text,color)}</div><p>Адресат: уполномоченный получатель<br>Поля: ${r.fields.map(f=>fieldNames[f]).join(", ")}<br>Цель: ${escapeHtml(r.reason)}</p>${controls&&item.status==="PENDING"?`<div class="button-row">${button("Подтвердить в приложении","consent-modal","primary",`data-request="${escapeHtml(r.id)}"`)}${button("Решение арбитра","arbiter-modal","secondary",`data-request="${escapeHtml(r.id)}"`)}</div>`:""}${controls&&item.status==="ROTATING"?`<div class="button-row">${button("Продолжить доставку и ротацию","resume","primary",`data-request="${escapeHtml(r.id)}"`)}</div>`:""}${controls&&item.status==="DENIED"?button("Создать новый запрос","go-request","secondary"):""}</div>`;
}
function lowerPanels() {
  const bets = ownBets().slice(-3).reverse();
  const cp=cupisClient(), shares=(role("cupis").shares || []).filter(s=>s.client_id===client()?.client_id);
  return `<div class="below-grid"><section class="panel"><div class="panel-head"><h2 class="panel-title">Что видит букмекер</h2>${tag("Без ФИО и документов","green")}</div>${bets.length?`<div class="mini-list">${bets.map(b=>`<div class="mini-row"><div><strong>${titles[b.quote.bookmaker]} · ${money(b.quote.stake)}</strong><small>${b.quote.event_id==="cup-final"?"Финал кубка":"Матч лиги"} · ${b.quote.odds}</small></div><div><code>${short(b.quote.pseudonym,13)}</code><br>${tag(({ACCEPTED:"Принята",WON:"Выигрыш",LOST:"Проигрыш",VOID:"Возврат",RESERVING:"Резерв"})[b.status],b.status==="WON"?"green":"")}</div></div>`).join("")}</div>`:'<div class="empty">Пока нет ставок.<br>После приёма здесь появятся только игровые данные.</div>'}</section><section class="panel"><div class="panel-head"><h2 class="panel-title">Что хранится в ЦУПИС</h2>${tag(cp?`Архив v${cp.archive.version}`:"Архив не создан","purple")}</div><div class="mini-list"><div class="mini-row"><div><strong>Персональная запись</strong><small>${cp?"Шифротекст AES-GCM":"Появится после регистрации"}</small></div>${tag(cp?"Зашифрована":"—",cp?"purple":"")}</div><div class="mini-row"><div><strong>Доли ключа в этом хранилище</strong><small>Для выбранного клиента</small></div><strong>${shares.length} / 3</strong></div><div class="mini-row"><div><strong>Полный ключ документов</strong><small>Не сохраняется постоянно</small></div>${tag("Отсутствует","green")}</div></div></section></div>`;
}
function visibilityPage() {
  const approved=(role("recipient").identity_reports||[]).some(r=>r.body.pseudonym===client()?.pseudonyms[r.body.bookmaker]);
  const cells={yes:'<span class="visibility-cell yes">● Видит</span>',no:'<span class="visibility-cell">— Нет</span>',sealed:'<span class="visibility-cell sealed">◈ Шифротекст</span>',own:'<span class="visibility-cell partial">Только своё</span>',allowed:'<span class="visibility-cell partial">Одобренные поля</span>'};
  const rows=[
    ["ФИО и документы","yes","sealed","no","no",approved?"allowed":"no"],
    ["Псевдонимы разных БК","yes","yes","own","no","own"],
    ["Содержание ставок","own","no","own","no","own"],
    ["Платёжные операции","own","yes","own","no","no"],
    ["Доля ключа документов","own","own","no","own","no"],
    ["Полный ключ документов","no","no","no","no","no"]
  ];
  return `<section class="panel"><div class="panel-head"><div><h2 class="panel-title">Кто действительно получает данные</h2><p class="panel-subtitle">Состояние для выбранного игрока · ${client()?escapeHtml(client().identity.full_name):"создайте игрока"}</p></div>${tag("Матрица доступа","purple")}</div>${client()?`<div class="detail-body">${chooseClient()}</div>`:""}<div class="matrix-wrap"><table class="matrix"><thead><tr><th>Данные</th><th>Клиент</th><th>ЦУПИС</th><th>Букмекер</th><th>Арбитр</th><th>Получатель</th></tr></thead><tbody>${rows.map(([name,...values])=>`<tr><td>${name}</td>${values.map(value=>`<td>${cells[value]}</td>`).join("")}</tr>`).join("")}</tbody></table></div><div class="matrix-note">ЦУПИС видит документы при регистрации. Полный ключ и открытая запись временно доступны доверенному компоненту раскрытия. Получатель сохраняет разрешённый результат.</div></section>${inspector()}<section class="panel wide-gap"><div class="limit-note"><strong>Границы демонстрации.</strong> Сервисы имеют разные базы и ключи, но работают под одним владельцем компьютера. Это не изоляция от администратора ОС. Криптография не мешает получателю сохранить уже раскрытые данные и не защищает от сговора двух хранителей.</div></section>`;
}
function inspector() {
  const data=role(selectedRole);
  const summaries={wallet:"Собственные документы, псевдонимы и подписанные квитанции. Клиентская доля хранится здесь, отдельно от ЦУПИС.",cupis:"В базе — зашифрованный архив, собственная доля, соответствия псевдонимов и условные счета. Открытые документы в этой проекции отсутствуют.",bookmaker_alpha:"Собственные игровые данные по псевдонимам. Нет документов, глобального идентификатора клиента и долей ключа.",bookmaker_beta:"У того же игрока здесь другой псевдоним. Данные Alpha и документы клиента не выдаются.",arbiter:"Метаданные собственной доли и журнал решений. Арбитр не хранит документы и историю ставок.",recipient:"Игровая отчётность и явно одобренные поля личности. Записи связываются по букмекеру и его псевдониму.",disclosure:"Запросы, их статусы и результаты ротации. Полные ключи и доли не выдаются через интерфейс."};
  const clean=Object.fromEntries(Object.entries(data).filter(([k])=>!["audit","online"].includes(k)));
  return `<section class="panel inspector"><div class="panel-head"><div><h2 class="panel-title">Инспектор участника</h2><p class="panel-subtitle">Фактический ответ собственного API роли · секретные значения исключены</p></div>${tag("Только чтение")}</div><div class="role-tabs">${Object.entries(titles).map(([r,n])=>`<button class="role-tab ${selectedRole===r?"active":""}" data-inspect-role="${r}">${n}</button>`).join("")}</div><div class="inspector-grid"><div class="inspector-summary"><span class="actor-icon">${icon(selectedRole)}</span><h3>${titles[selectedRole]}</h3><p>${summaries[selectedRole]}</p><div class="code-box"><div class="code-label">ОТДЕЛЬНОЕ ХРАНИЛИЩЕ</div>${escapeHtml(data.database||"Недоступно")}</div><p>Вы находитесь в привилегированной панели наблюдателя. Обычный сервис букмекера не может запросить эту проекцию другой роли.</p></div><pre class="inspector-json">${escapeHtml(JSON.stringify(clean,null,2))}</pre></div></section>`;
}
function protocolPage() {
  const events=Object.entries(snapshot.roles).flatMap(([r,data])=>(data.audit||[]).map(e=>({...e,role:r}))).sort((a,b)=>b.ts.localeCompare(a.ts)).slice(0,70);
  const names={ARCHIVE_ENCRYPTED:"Архив зашифрован",SHARES_DISTRIBUTED:"Ключ разделён между хранителями",SHARE_STORED:"Собственная доля сохранена",CLIENT_REGISTERED:"Клиент зарегистрирован",BET_ACCEPTED:"Ставка принята",BET_RECEIPT_VERIFIED:"Подпись квитанции проверена",FUNDS_RESERVED:"Условные средства зарезервированы",FUNDS_SETTLED:"Условные средства рассчитаны",EVENT_SETTLED:"Событие рассчитано",DISCLOSURE_REQUESTED:"Создан адресный запрос",ONE_SHARE_PROBE_BLOCKED:"Восстановление по одной доле отклонено",TWO_SHARES_APPROVED:"Получены две согласованные доли",KEY_ROTATED:"Ключ архива заменён",DISCLOSURE_APPROVED:"Раскрытие одобрено",DISCLOSURE_DENIED:"Арбитр отказал",IDENTITY_REPORT_RECEIVED:"Разрешённые поля доставлены",GAME_REPORT_RECEIVED:"Игровой отчёт доставлен",DISCLOSURE_DELIVERED_AND_ROTATED:"Доставка и ротация завершены",MESSAGE_PROCESSED:"Защищённое сообщение обработано",MESSAGE_REJECTED:"Сообщение отклонено",ADMISSION_CHANGED:"Допуск изменён"};
  return `<section class="panel"><div class="panel-head"><div><h2 class="panel-title">Журнал взаимодействия</h2><p class="panel-subtitle">Метаданные реальных операций. Без документов, сырых долей и ключей.</p></div>${tag(`${events.length} последних событий`)}</div>${events.length?`<div class="table-overflow"><table class="protocol-table"><thead><tr><th>Время</th><th>Участник</th><th>Событие</th><th>Подробности</th></tr></thead><tbody>${events.map(e=>`<tr><td>${new Date(e.ts).toLocaleTimeString("ru-RU")}</td><td>${titles[e.role]}</td><td><strong>${names[e.action]||escapeHtml(e.action)}</strong><small>Хэш ${short(e.hash,14)}</small></td><td>${Object.entries(e.meta).map(([k,v])=>`<small>${escapeHtml(k)}: ${escapeHtml(typeof v==="object"?JSON.stringify(v):v)}</small>`).join("")}</td></tr>`).join("")}</tbody></table></div>`:'<div class="empty">Выполните первый шаг — журнал заполнится фактическими событиями.</div>'}<div class="matrix-note">У каждой роли свой связанный хэшами журнал. Это не внешне закреплённый неизменяемый реестр.</div></section>`;
}
function render() {
  if (!snapshot) return;
  const online=Object.values(snapshot.roles).filter(r=>r.online).length;
  $("#online-count").textContent=`${online} из 7 сервисов доступны`;
  $("#connection-error").hidden=online===7;
  if(online!==7) $("#connection-error").textContent="Часть сервисов недоступна. Состояние не считается полным; проверьте локальные процессы.";
  const pageMeta={scenario:["Демонстрация","Ставка видна.<br><span>Личность защищена.</span>","Посмотрите, как участники работают вместе,<br class=\"desktop-only\"> не собирая документы и ключи в одном месте."],visibility:["Видимость данных","У каждого участника —<br><span>своя граница доступа.</span>","Прозрачно показываем, что хранится в каждом контуре<br class=\"desktop-only\"> и что меняется после разрешённого раскрытия."],protocol:["Журнал обмена","Каждое действие<br><span>оставляет проверяемый след.</span>","Наблюдайте за фактическим обменом между сервисами.<br class=\"desktop-only\"> Секреты не попадают в журнал." ]}[page];
  $("#page-label").textContent=pageMeta[0]; $("#page-title").innerHTML=pageMeta[1]; $("#page-description").innerHTML=pageMeta[2];
  document.querySelectorAll("[data-page]").forEach(el=>el.classList.toggle("active",el.dataset.page===page));
  $("#participant-nav").innerHTML=Object.entries(titles).map(([r,n])=>`<button class="participant-button ${selectedRole===r?"selected":""}" data-role="${r}"><span class="participant-mini-icon">${r.startsWith("bookmaker")?"▣":r==="wallet"?"♙":r==="cupis"?"▥":r==="arbiter"?"⚖":r==="recipient"?"▤":"◇"}</span>${n}<span class="dot ${role(r).online?"online":"offline"}"></span></button>`).join("");
  if(page==="scenario") {const step=viewStep ?? progress();$("#app").innerHTML=flow()+`<div class="workspace-grid">${journey(step)}${detail(step)}</div>`+lowerPanels();}
  else $("#app").innerHTML=page==="visibility"?visibilityPage():protocolPage();
}
function openModal(body) { $("#modal-content").innerHTML=`<div class="modal-inner">${body}</div>`; $("#modal").showModal(); }
function closeModal() { $("#modal").close(); }
function modalHead(title,subtitle) {return `<div class="modal-top"><div><div class="section-kicker">${subtitle}</div><h2 id="modal-title">${title}</h2></div><button class="icon-button" data-action="close-modal" aria-label="Закрыть">×</button></div>`;}
function enrollModal() {
  const n=clients().length;
  openModal(`${modalHead("Создать демо-игрока","СИНТЕТИЧЕСКАЯ ИДЕНТИФИКАЦИЯ")}<p>Используйте только вымышленные данные. Кошелёк клиента будет храниться отдельно от архива ЦУПИС.</p><label><span class="field-label">Имя</span><input id="enroll-name" value="${n?"Мария Тестовая":"Алексей Демонстрационный"}" maxlength="120"></label><div class="field-row"><label><span class="field-label">Вымышленный документ</span><input id="enroll-passport" value="DEMO-${String(n+1).padStart(4,"0")}" maxlength="40"></label><label><span class="field-label">Возраст</span><input id="enroll-age" type="number" min="18" max="120" value="25"></label></div><div class="privacy-note">ЦУПИС зашифрует запись и распределит доли. На условный счёт будет начислено 3 000 ₽ для демонстрации.</div><div class="button-row">${button("Отмена","close-modal","secondary")}${button("Создать и зашифровать","confirm-enroll")}</div>`);
}
function consentModal(id) {
  const item=(role("disclosure").requests||[]).find(r=>r.request.id===id); if(!item) return;
  const r=item.request;
  openModal(`${modalHead("Разрешить передачу данных?","ПОДТВЕРЖДЕНИЕ В ПРИЛОЖЕНИИ КЛИЕНТА")}<p>Вы подтверждаете конкретный запрос. Приложение подпишет одобрение и отправит свою долю зашифрованно компоненту раскрытия.</p><div class="modal-detail"><span>Получатель</span><strong>Уполномоченный получатель</strong></div><div class="modal-detail"><span>Поля</span><strong>${r.fields.map(f=>fieldNames[f]).join(", ")}</strong></div><div class="modal-detail"><span>Цель</span><strong>${escapeHtml(r.reason)}</strong></div><div class="modal-detail"><span>Версия ключа</span><strong>v${r.version} → v${r.version+1}</strong></div><p>После доставки ключ и доли будут заменены. Уже переданные данные могут сохраняться у получателя.</p><div class="button-row">${button("Отмена","close-modal","secondary")}${button("Разрешить передачу","confirm-approve","primary",`data-request="${escapeHtml(id)}"`)}</div>`);
}
function arbiterModal(id) {
  openModal(`${modalHead("Решение независимого арбитра","ИСКЛЮЧИТЕЛЬНОЕ РАСКРЫТИЕ")}<p>Моделируем проверку основания без участия клиента. Настоящую юридическую процедуру стенд не выполняет.</p><label><span class="field-label">Проверенное демонстрационное основание</span><input id="arbiter-basis" value="Синтетическое решение №42"></label><div class="button-row">${button("Отказать","confirm-deny","danger",`data-request="${escapeHtml(id)}"`)}${button("Одобрить и передать долю","confirm-arbiter","primary",`data-request="${escapeHtml(id)}"`)}</div>`);
}
document.addEventListener("change", e=>{
  if(e.target.id==="client-picker") {selectedClient=e.target.value;viewStep=null;render();}
  if(e.target.dataset.draft) {draft[e.target.dataset.draft]=e.target.value;if(e.target.dataset.draft!=="reason"&&e.target.dataset.draft!=="stake") render();}
  if(e.target.name==="identity-field") draft.fields=Array.from(document.querySelectorAll("[name=identity-field]:checked"),el=>el.value);
});
document.addEventListener("input",e=>{if(e.target.dataset.draft)draft[e.target.dataset.draft]=e.target.value;});
document.addEventListener("click",async e=>{
  const el=e.target.closest("button");if(!el||el.disabled) return;
  if(el.dataset.page){page=el.dataset.page;render();return;}
  if(el.dataset.role){selectedRole=el.dataset.role;page="visibility";render();return;}
  if(el.dataset.inspectRole){selectedRole=el.dataset.inspectRole;render();return;}
  if(el.dataset.step!==undefined){viewStep=Number(el.dataset.step);render();return;}
  const action=el.dataset.action;if(!action||busy)return;
  if(action==="close-modal"){closeModal();return;}
  if(action==="refresh"){await load().catch(err=>toast(err.message,true));return;}
  if(action==="enroll-modal"){enrollModal();return;}
  if(action==="go-bet"){viewStep=1;render();return;}
  if(action==="go-request"){viewStep=3;render();return;}
  if(action==="go-visibility"){page="visibility";render();return;}
  if(action==="confirm-enroll"){
    const data={client_id:uid(),full_name:$("#enroll-name").value,passport:$("#enroll-passport").value,age:Number($("#enroll-age").value)};
    closeModal();await act("enroll",data,"Игрок создан. Архив зашифрован, доли доставлены трём хранителям.");return;
  }
  if(action==="reset"){
    openModal(`${modalHead("Начать демонстрацию заново?","СБРОС СИНТЕТИЧЕСКИХ ДАННЫХ")}<p>Все созданные в стенде игроки, ставки, доли и отчёты будут удалены. Ключи сервисов сохранятся.</p><div class="button-row">${button("Отмена","close-modal","secondary")}${button("Сбросить стенд","confirm-reset","danger")}</div>`);return;
  }
  if(action==="confirm-reset"){closeModal();selectedClient="";await act("reset",{confirmation:"RESET_SYNTHETIC_DEMO"},"Стенд очищен. Можно начать новый сценарий.");return;}
  if(!client()){toast("Сначала создайте демо-игрока.",true);return;}
  if(action==="bet"){
    const rub=Number(draft.stake);if(!Number.isFinite(rub)||rub<=0){toast("Введите положительную сумму.",true);return;}
    await act("bet",{client_id:client().client_id,bookmaker:draft.bookmaker,event_id:draft.event_id,selection:draft.selection,stake:Math.round(rub*100),operation_id:uid()},"Ставка принята. Подпись квитанции проверена клиентом.");return;
  }
  if(action==="probe"){await act("probe",{client_id:client().client_id},"Одна доля: восстановление ключа отклонено.");viewStep=2;render();return;}
  if(action==="request"){
    if(!draft.fields.length){toast("Выберите хотя бы одно поле.",true);return;}
    await act("request",{client_id:client().client_id,bookmaker:draft.bookmaker,fields:draft.fields,reason:draft.reason,operation_id:uid()},"Адресный запрос создан. Ожидаем решение клиента или арбитра.");return;
  }
  if(action==="consent-modal"){consentModal(el.dataset.request);return;}
  if(action==="arbiter-modal"){arbiterModal(el.dataset.request);return;}
  if(action==="confirm-approve"){closeModal();await act("approve",{request_id:el.dataset.request},"Данные доставлены. Новый ключ и три новые доли сохранены.");return;}
  if(action==="confirm-deny"||action==="confirm-arbiter"){
    const data={request_id:el.dataset.request,decision:action==="confirm-deny"?"DENY":"APPROVE",basis:$("#arbiter-basis").value};
    closeModal();await act("arbiter",data,action==="confirm-deny"?"Арбитр отказал. Доля не выдана.":"Арбитр одобрил раскрытие. Данные доставлены, ключ заменён.");return;
  }
  if(action==="resume"){await act("resume",{request_id:el.dataset.request},"Доставка и ротация завершены.");return;}
  if(action==="settle-modal"){
    openModal(`${modalHead("Рассчитать событие","УСЛОВНЫЕ ДЕНЬГИ · СИНТЕТИЧЕСКИЙ РЕЗУЛЬТАТ")}<p>${titles[draft.bookmaker]} · ${draft.event_id==="cup-final"?"Финал кубка":"Матч лиги"}. Будут рассчитаны только ставки на это событие у выбранной БК.</p><label><span class="field-label">Результат события</span><select id="outcome"><option value="HOME_WIN">Победа хозяев</option><option value="AWAY_WIN">Победа гостей</option><option value="VOID">Отмена / возврат</option></select></label><div class="button-row">${button("Отмена","close-modal","secondary")}${button("Рассчитать и отправить отчёт","confirm-settle")}</div>`);return;
  }
  if(action==="confirm-settle"){const outcome=$("#outcome").value;closeModal();await act("settle",{bookmaker:draft.bookmaker,event_id:draft.event_id,outcome},"Событие рассчитано. Игровой отчёт доставлен получателю.");}
});
$("#modal").addEventListener("click",e=>{if(e.target===$("#modal"))closeModal();});
load().catch(err=>{$("#app").innerHTML='<div class="empty">Не удалось подключиться. Проверьте запуск сервисов и обновите страницу.</div>';toast(err.message,true);});
