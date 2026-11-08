// Sentinela: painel web do CrowdSec. Todo texto vem do servidor e entra via textContent (nada de innerHTML):
// caminhos, user-agents e hostnames vêm de quem atacou.
(function () {
    'use strict';
    var NS = 'http://www.w3.org/2000/svg';
    var BASE = document.body.getAttribute('data-base') || '';  // subcaminho no NPM, ex.: /defesa
    var atividade = false;
    var aba = 'geral';
    var estado = { alertas: [], bans: [], pode: false };
    var timerAtualizacao = null;

    function pararAtualizacao() { if (timerAtualizacao) clearInterval(timerAtualizacao); timerAtualizacao = null; }

    // ------------------------------------------------------------ utilidades
    function $(id) { return document.getElementById(id); }
    function el(tag, cls, txt) {
        var e = document.createElement(tag);
        if (cls) e.className = cls;
        if (txt !== undefined) e.textContent = txt;
        return e;
    }
    function limpa(n) { while (n.firstChild) n.removeChild(n.firstChild); }
    function fmt(n) { return Number(n).toLocaleString('pt-BR'); }
    function semPrefixo(v) { return String(v).replace(/^crowdsecurity\//, ''); }
    function svg(tag, attrs) {
        var e = document.createElementNS(NS, tag);
        Object.keys(attrs || {}).forEach(function (k) { e.setAttribute(k, attrs[k]); });
        return e;
    }
    function aviso(msg) {
        var a = $('aviso');
        a.hidden = !msg;
        a.textContent = msg || '';
    }
    function atualizado(txt) { $('atualizado').textContent = 'atualizado ' + txt; }
    function janela() { return $('janela').value; }
    function fmtHa(s) {
        if (s === null || s === undefined) return '—';
        if (s < 90) return 'há ' + s + ' s';
        if (s < 5400) return 'há ' + Math.round(s / 60) + ' min';
        if (s < 129600) return 'há ' + Math.round(s / 3600) + ' h';
        return 'há ' + Math.round(s / 86400) + ' d';
    }

    // x = {ok, d}. 401 = sessão acabou. 'usuario' = ação do usuário (estende a sessão; o polling sozinho não).
    function api(caminho, usuario) {
        var h = { 'Accept': 'application/json' };
        if (usuario || atividade) { h['X-Atividade'] = '1'; atividade = false; }
        return fetch(BASE + caminho, { credentials: 'same-origin', headers: h })
            .then(function (r) {
                if (r.status === 401) { location.href = BASE + '/login'; throw new Error('sessao'); }
                if (r.status === 403) {  // acesso negado: parar de repetir (os 403 seguidos contam como varredura no CrowdSec)
                    pararAtualizacao();
                    aviso('Acesso negado: este endereço de rede não está liberado para o painel. Fale com o administrador do painel e recarregue a página depois.');
                    throw new Error('sessao');
                }
                return r.json().then(function (d) { return { ok: r.ok, d: d }; });
            });
    }
    function falha(e) { if (e.message !== 'sessao') aviso('Sem conexão com o painel.'); }

    // ------------------------------------------------------------ blocos genéricos
    function kpis(box, pares) {
        limpa(box);
        pares.forEach(function (x) {
            var c = el('div', 'kpi');
            c.appendChild(el('div', 'valor' + (typeof x[1] === 'number' ? '' : ' texto'), typeof x[1] === 'number' ? fmt(x[1]) : x[1]));
            c.appendChild(el('div', 'rotulo', x[0]));
            if (x[3]) c.appendChild(x[3]);
            if (x[2]) { c.title = x[2]; }
            box.appendChild(c);
        });
    }

    function barras(id, lista, grupo) {
        lista = lista.map(function (x) { return [semPrefixo(x[0]), x[1], x[0]]; });
        var box = $(id);
        limpa(box);
        box.className = 'barras';
        if (!lista.length) { box.appendChild(el('div', 'vazio', 'Sem dados no período.')); return; }
        var max = Math.max.apply(null, lista.map(function (x) { return x[1]; })) || 1;
        lista.forEach(function (x) {
            var l = el('div', 'linha');
            var nome = el('div', 'nome', x[0]);
            nome.title = x[0];
            if (grupo) marcar(nome, grupo, x[2]);
            var tr = el('div', 'trilho'), pr = el('div', 'preench');
            pr.style.width = Math.max(2, Math.round(x[1] * 100 / max)) + '%';
            tr.appendChild(pr);
            l.appendChild(nome); l.appendChild(tr); l.appendChild(el('div', 'n', fmt(x[1])));
            box.appendChild(l);
        });
    }

    // Tabela com ordenação por clique no cabeçalho, linhas clicáveis e limite de linhas.
    // cols: {k, t, num, dir, ip, ord (chave de ordenação), fmt(v, linha), cls}
    function tabela(t, cols, linhas, o) {
        o = o || {};
        var ord = t._ord || (t._ord = { k: o.ordem || null, asc: !!o.asc });
        limpa(t);
        if (!linhas.length) {
            var tr0 = el('tr'), td0 = el('td', 'vazio', o.vazio || 'Sem dados.');
            td0.colSpan = cols.length;
            tr0.appendChild(td0); t.appendChild(tr0);
            return;
        }
        var dados = linhas.slice();
        if (ord.k) {
            var col = cols.filter(function (c) { return c.k === ord.k; })[0] || {};
            var chave = col.ord || ord.k;
            dados.sort(function (a, b) {
                var x = a[chave], y = b[chave], r;
                if (typeof x === 'number' && typeof y === 'number') r = x - y;
                else r = String(x === null || x === undefined ? '' : x).localeCompare(String(y === null || y === undefined ? '' : y), 'pt-BR', { numeric: true });
                return ord.asc ? r : -r;
            });
        }
        var cab = el('tr');
        cols.forEach(function (c) {
            var th = el('th', (c.num || c.dir ? 'num' : '') + (o.ordenar === false ? '' : ' ord'));
            th.textContent = c.t + (ord.k === c.k ? (ord.asc ? ' ▲' : ' ▼') : '');
            if (o.ordenar !== false) {
                th.tabIndex = 0;
                var ordenar = function () {
                    if (ord.k === c.k) ord.asc = !ord.asc; else { ord.k = c.k; ord.asc = !(c.num || c.dir); }
                    tabela(t, cols, linhas, o);
                };
                th.addEventListener('click', ordenar);
                th.addEventListener('keydown', function (ev) { if (ev.key === 'Enter') ordenar(); });
            }
            cab.appendChild(th);
        });
        var thead = el('thead'); thead.appendChild(cab); t.appendChild(thead);
        var tb = el('tbody'), lim = o.limite || 1000;
        dados.slice(0, lim).forEach(function (l) {
            var tr = el('tr');
            if (o.id && l[o.id] !== null && l[o.id] !== undefined) {
                tr.className = 'clicavel';
                tr.tabIndex = 0;
                var abrir = function () { detalhe(l[o.id]); };
                tr.addEventListener('click', abrir);
                tr.addEventListener('keydown', function (ev) { if (ev.key === 'Enter') abrir(); });
            }
            cols.forEach(function (c) {
                var v = l[c.k];
                var txt = c.fmt ? c.fmt(v, l) : (c.num ? fmt(v) : (v === undefined || v === null || v === '' ? '—' : String(v)));
                var td = el('td', (c.num || c.dir ? 'num ' : '') + (c.ip ? 'ip ' : '') + (c.cls || ''), txt);
                if (c.botao) { td.textContent = ''; var bt = c.botao(l); if (bt) td.appendChild(bt); }
                var grupo = c.cen ? 'cenarios' : (c.ip && o.id ? 'ip' : (c.glos || null));
                if (grupo && v !== undefined && v !== null && v !== '') marcar(td, grupo, v, o.id ? l[o.id] : null);
                tr.appendChild(td);
            });
            tb.appendChild(tr);
        });
        if (dados.length > lim) {
            var trm = el('tr'), tdm = el('td', 'vazio', 'Mostrando ' + fmt(lim) + ' de ' + fmt(dados.length) + ' linhas: refine os filtros ou exporte o CSV.');
            tdm.colSpan = cols.length;
            trm.appendChild(tdm); tb.appendChild(trm);
        }
        t.appendChild(tb);
    }

    function preencherSelect(sel, valores, rotulo, mapa) {
        var atual = sel.value;
        limpa(sel);
        var o0 = el('option', '', rotulo); o0.value = '';
        sel.appendChild(o0);
        valores.forEach(function (v) { var o = el('option', '', mapa ? mapa(v) : v); o.value = v; sel.appendChild(o); });
        sel.value = valores.indexOf(atual) >= 0 ? atual : '';
    }

    // ------------------------------------------------------------ gráficos
    function grafico(serie, id) {
        var box = $(id || 'grafico');
        limpa(box);
        var W = 960, H = 190, ml = 34, mb = 22, mt = 8, mr = 6;
        var s = svg('svg', { viewBox: '0 0 ' + W + ' ' + H, role: 'img', 'aria-label': 'Alertas ao longo do tempo' });
        var max = Math.max.apply(null, serie.map(function (x) { return x.n; }).concat([1]));
        var topo = max <= 4 ? max : Math.ceil(max / 4) * 4;
        var h = H - mb - mt, w = W - ml - mr;
        for (var i = 0; i <= 4; i++) {
            var y = mt + h - (h * i / 4);
            s.appendChild(svg('line', { x1: ml, x2: W - mr, y1: y, y2: y, 'class': 'grade-h' }));
            var t = svg('text', { x: ml - 6, y: y + 4, 'text-anchor': 'end', 'class': 'eixo' });
            t.textContent = String(Math.round(topo * i / 4));
            s.appendChild(t);
        }
        var n = serie.length, passo = w / n, lg = Math.max(1, passo * 0.72);
        serie.forEach(function (p, k) {
            var bh = topo ? h * p.n / topo : 0;
            var r = svg('rect', { x: ml + k * passo + (passo - lg) / 2, y: mt + h - bh, width: lg, height: Math.max(bh, p.n ? 1 : 0), 'class': 'b' });
            var tt = svg('title', {});
            tt.textContent = p.d + ': ' + p.n + ' alerta(s)';
            r.appendChild(tt);
            s.appendChild(r);
        });
        var cada = Math.max(1, Math.ceil(n / 12));
        serie.forEach(function (p, k) {
            if (k % cada) return;
            var tx = svg('text', { x: ml + k * passo + passo / 2, y: H - 6, 'text-anchor': 'middle', 'class': 'eixo' });
            tx.textContent = p.r;
            s.appendChild(tx);
        });
        box.appendChild(s);
    }

    var CORES_ROSCA = ['#0f2a43', '#1f6fd0', '#2f80ed', '#2a6fa8', '#8ecae6', '#1d4e7a', '#a9c4de', '#9aa0a6'];
    function rosca(lista) {
        var box = $('rosca');
        limpa(box);
        if (!lista.length) { box.appendChild(el('div', 'vazio', 'Sem dados no período.')); return; }
        var total = lista.reduce(function (a, x) { return a + x[1]; }, 0) || 1;
        var s = svg('svg', { viewBox: '0 0 100 100', role: 'img', 'aria-label': 'Proporção de alertas por cenário' });
        var R = 38, C = 2 * Math.PI * R, acum = 0;
        var ul = el('ul', '');
        lista.forEach(function (x, k) {
            var f = x[1] / total, cor = CORES_ROSCA[k % CORES_ROSCA.length];
            var c = svg('circle', { cx: 50, cy: 50, r: R, 'class': 'fatia', stroke: cor, 'stroke-dasharray': (f * C) + ' ' + (C - f * C),
                'stroke-dashoffset': -acum * C, transform: 'rotate(-90 50 50)' });
            var tt = svg('title', {});
            tt.textContent = semPrefixo(x[0]) + ': ' + x[1] + ' (' + Math.round(f * 1000) / 10 + '%)';
            c.appendChild(tt);
            s.appendChild(c);
            acum += f;
            var li = el('li', '');
            var i = el('i', ''); i.style.background = cor;
            var nome = el('span', '', semPrefixo(x[0])); nome.title = x[0];
            marcar(nome, 'cenarios', x[0]);
            li.appendChild(i); li.appendChild(nome); li.appendChild(el('b', '', Math.round(f * 100) + '%'));
            ul.appendChild(li);
        });
        var t1 = svg('text', { x: 50, y: 52, 'text-anchor': 'middle', 'class': 'centro' }); t1.textContent = fmt(total);
        var t2 = svg('text', { x: 50, y: 62, 'text-anchor': 'middle', 'class': 'centro-s' }); t2.textContent = 'alertas';
        s.appendChild(t1); s.appendChild(t2);
        box.appendChild(s); box.appendChild(ul);
    }

    function mapaCalor(m) {
        var box = $('mapa'), dias = ['Seg', 'Ter', 'Qua', 'Qui', 'Sex', 'Sáb', 'Dom'], max = 1;
        limpa(box);
        m.forEach(function (l) { l.forEach(function (v) { if (v > max) max = v; }); });
        var g = el('div', 'mapa-grade');
        g.appendChild(el('div', 'mc-rot', ''));
        for (var h = 0; h < 24; h++) g.appendChild(el('div', 'mc-h', h % 3 === 0 ? String(h) : ''));
        m.forEach(function (linha, i) {
            g.appendChild(el('div', 'mc-rot', dias[i]));
            linha.forEach(function (v, hora) {
                var c = el('div', 'mc' + (v ? '' : ' zero'));
                if (v) c.style.background = 'rgba(181, 42, 55, ' + (0.15 + 0.85 * v / max).toFixed(2) + ')';
                c.title = dias[i] + ' ' + hora + 'h: ' + v + ' alerta(s)';
                g.appendChild(c);
            });
        });
        box.appendChild(g);
    }

    // ------------------------------------------------------------ balão de explicação (mouse, teclado e toque)
    var GL = window.GLOSSARIO || { cenarios: {}, acoes: {}, origens: {} };
    var dicaEl = null, dicaAlvo = null, dicaTimer = null, cacheAlerta = {};

    function cortar(s, n) { s = String(s); return s.length > n ? s.slice(0, n - 1) + '…' : s; }

    function marcar(e, grupo, chave, alerta) {
        e.setAttribute('data-g', grupo);
        e.setAttribute('data-k', String(chave));
        if (alerta !== null && alerta !== undefined) e.setAttribute('data-a', String(alerta));
        e.removeAttribute('title');  // o title nativo apareceria junto com o balão
        e.classList.add('glos');
        e.tabIndex = 0;
    }

    // Um alerta nunca muda depois de criado: guarda a resposta para o balão e o detalhe usarem a mesma busca.
    function buscarAlerta(id, usuario) {
        if (!cacheAlerta[id]) {
            if (Object.keys(cacheAlerta).length > 150) cacheAlerta = {};
            cacheAlerta[id] = api('/api/alerta?id=' + encodeURIComponent(id), usuario).then(function (x) {
                if (!x.ok) delete cacheAlerta[id];
                return x;
            }, function (e) { delete cacheAlerta[id]; throw e; });
        }
        return cacheAlerta[id];
    }

    // O que o IP tentou: pedidos mais repetidos, programa usado e alvo (vem pronto do servidor em d.resumo).
    function tentativas(box, d) {
        var r = d.resumo;
        if (!r || !r.top || !r.top.length) { box.appendChild(el('p', 'dica-n', 'O CrowdSec não guardou os pedidos deste alerta.')); return; }
        var ul = el('ul', 'tent-lista');
        r.top.forEach(function (x) {
            var li = el('li', 'tent-item');
            li.appendChild(el('code', '', cortar(x.req, 74)));
            if (x.status) li.appendChild(el('span', 'tent-st', x.status));
            if (x.n > 1) li.appendChild(el('span', 'tent-n', '×' + x.n));
            ul.appendChild(li);
        });
        box.appendChild(ul);
        if (r.distintos > r.top.length) box.appendChild(el('p', 'dica-n', '+ ' + (r.distintos - r.top.length) + ' outros pedidos diferentes'));
        if (r.agentes.length) box.appendChild(el('p', 'dica-n', 'Programa usado: ' + cortar(r.agentes[0][0], 90)));
        if (r.hosts.length) box.appendChild(el('p', 'dica-n', 'Alvo: ' + r.hosts.map(function (h) { return h[0]; }).join(', ')));
        box.appendChild(el('p', 'dica-n', d.mostrados < d.total ? 'Mostrando ' + d.mostrados + ' de ' + fmt(d.total) + ' pedidos que o CrowdSec guardou.' : d.mostrados + ' pedido(s) registrado(s).'));
    }

    function posicionarDica() {
        if (!dicaAlvo) return;
        var r = dicaAlvo.getBoundingClientRect(), d = dicaEl.getBoundingClientRect();
        var x = Math.min(Math.max(8, r.left), Math.max(8, window.innerWidth - d.width - 8));
        var y = r.bottom + 8;
        if (y + d.height > window.innerHeight - 8) y = Math.max(8, r.top - d.height - 8);
        dicaEl.style.left = x + 'px';
        dicaEl.style.top = y + 'px';
    }

    function esconderDica() {
        clearTimeout(dicaTimer);
        dicaAlvo = null;
        if (dicaEl) dicaEl.hidden = true;
    }

    function mostrarDica(alvo) {
        if (alvo === dicaAlvo) return;
        dicaAlvo = alvo;
        var g = alvo.getAttribute('data-g'), k = alvo.getAttribute('data-k'), a = alvo.getAttribute('data-a');
        limpa(dicaEl);
        var rodape = '';
        if (g === 'cenarios') {
            var c = GL.cenarios[k], cve = /CVE-\d{4}-\d+/i.exec(k);
            if (!c && cve) c = { t: 'Falha conhecida ' + cve[0].toUpperCase(), k: 'gatilho', d: 'Tentativa de explorar a falha de segurança ' + cve[0].toUpperCase() + '. Se você não usa o produto afetado, é um robô testando falhas conhecidas em tudo que encontra.' };
            if (!c) c = { t: semPrefixo(k), d: 'Regra de detecção do CrowdSec ainda sem explicação cadastrada em português. Veja a descrição na aba Cenários.' };
            dicaEl.appendChild(el('strong', 'dica-t', c.t));
            dicaEl.appendChild(el('p', 'dica-nome', k));
            dicaEl.appendChild(el('p', 'dica-d', c.d));
            rodape = c.k === 'gatilho' ? 'Dispara na primeira requisição que casar com o padrão.'
                : c.k === 'condicional' ? 'Acompanha o IP por um tempo antes de decidir.'
                : c.k === 'balde' ? 'Dispara quando o mesmo IP repete isso acima do limite' + (c.cap ? ' (balde de ' + c.cap + ', esvazia 1 a cada ' + c.leak + ')' : '') + '.' : '';
        } else if (g === 'acoes' || g === 'origens') {
            var x = GL[g][k] || { t: k, d: 'Sem explicação cadastrada.' };
            dicaEl.appendChild(el('strong', 'dica-t', x.t));
            dicaEl.appendChild(el('p', 'dica-d', x.d));
        } else if (g === 'ip') {
            dicaEl.appendChild(el('strong', 'dica-t', 'IP ' + k));
        }
        if (rodape) dicaEl.appendChild(el('p', 'dica-r', rodape));
        if (a) {
            var sec = el('div', 'dica-tent');
            sec.appendChild(el('h4', '', 'O que este IP tentou fazer'));
            sec.appendChild(el('p', 'dica-n', 'Carregando…'));
            dicaEl.appendChild(sec);
            buscarAlerta(a, false).then(function (r) {
                if (dicaAlvo !== alvo) return;  // o mouse já saiu
                limpa(sec);
                if (!r.ok) { sec.appendChild(el('p', 'dica-n', 'Não foi possível carregar os pedidos deste alerta.')); posicionarDica(); return; }
                sec.appendChild(el('h4', '', 'O que ' + r.d.ip + (r.d.pais && r.d.pais !== '--' ? ' (' + r.d.pais + ')' : '') + ' tentou fazer'));
                tentativas(sec, r.d);
                posicionarDica();
            }).catch(function () { /* sessão ou rede: o balão já mostra a explicação */ });
        }
        if (g === 'cenarios' || g === 'ip') dicaEl.appendChild(el('p', 'dica-r', a ? 'Clique na linha para ver todos os pedidos.' : ''));
        dicaEl.hidden = false;
        posicionarDica();
    }

    // ------------------------------------------------------------ colunas reutilizadas
    var COLS_ALERTAS = [{ k: 'quando', t: 'Quando', ord: 't' }, { k: 'ip', t: 'IP', ip: 1 }, { k: 'pais', t: 'País' },
        { k: 'as', t: 'Rede (AS)' }, { k: 'cenario', t: 'Cenário', fmt: semPrefixo, cen: 1 }, { k: 'eventos', t: 'Eventos', num: 1 },
        { k: 'decisao', t: 'Decisão', glos: 'acoes' }, { k: 'expira', t: 'Expira em', dir: 1 }];
    var COLS_BANS = [{ k: 'ip', t: 'IP / valor', ip: 1 }, { k: 'escopo', t: 'Escopo' }, { k: 'pais', t: 'País' }, { k: 'as', t: 'Rede (AS)' },
        { k: 'cenario', t: 'Cenário', fmt: semPrefixo, cen: 1 }, { k: 'tipo', t: 'Ação', glos: 'acoes' }, { k: 'origem', t: 'Origem', glos: 'origens' },
        { k: 'eventos', t: 'Eventos', num: 1 }, { k: 'expira', t: 'Expira em', dir: 1, ord: 'restante_s' }];

    // ------------------------------------------------------------ detalhe de um alerta (janela)
    function fechar() { $('modal').hidden = true; limpa($('modal')); }

    function detalhe(id) {
        var m = $('modal');
        limpa(m);
        m.hidden = false;
        var caixa = el('div', 'caixa');
        caixa.appendChild(el('p', 'vazio', 'Carregando eventos…'));
        m.appendChild(caixa);
        buscarAlerta(id, true).then(function (x) {
            limpa(caixa);
            var cab = el('div', 'caixa-cab');
            var fecha = el('button', 'fechar', 'Fechar');
            fecha.type = 'button';
            fecha.addEventListener('click', fechar);
            if (!x.ok) {
                cab.appendChild(el('h2', '', 'Alerta'));
                cab.appendChild(fecha);
                caixa.appendChild(cab);
                caixa.appendChild(el('p', 'erro', x.d.erro || 'Falha ao carregar o alerta.'));
                return;
            }
            var d = x.d;
            var h2 = el('h2', '', semPrefixo(d.cenario) + ' · ' + d.ip);
            marcar(h2, 'cenarios', d.cenario);
            cab.appendChild(h2);
            var acoes = el('div', 'acoes');
            var hist = el('button', 'botao', 'Histórico do IP');
            hist.type = 'button';
            hist.addEventListener('click', function () { fechar(); mostrar('ip', true); consultarIp(d.ip); });
            acoes.appendChild(hist); acoes.appendChild(fecha);
            cab.appendChild(acoes);
            caixa.appendChild(cab);
            var resumo = el('div', 'resumo');
            [['País', d.pais], ['Rede (AS)', d.as], ['Início', d.inicio], ['Fim', d.fim], ['Eventos do alerta', fmt(d.total)],
             ['Decisão', d.decisoes.map(function (z) { return z.tipo + ' (' + z.expira + ')'; }).join(', ')],
             ['Mensagem', d.mensagem], ['Máquina', d.maquina ? d.maquina.slice(0, 8) + '…' : '']
            ].forEach(function (par) {
                var c = el('div', 'par');
                c.appendChild(el('span', 'rot', par[0]));
                c.appendChild(el('span', 'val', par[1] || '—'));
                resumo.appendChild(c);
            });
            caixa.appendChild(resumo);
            var tent = el('div', 'tent');
            tent.appendChild(el('h3', '', 'O que este IP tentou fazer'));
            tentativas(tent, d);
            caixa.appendChild(tent);
            caixa.appendChild(el('p', 'nota', d.mostrados < d.total
                ? 'Mostrando ' + d.mostrados + ' de ' + fmt(d.total) + ' eventos: o CrowdSec guarda só os que dispararam o cenário.'
                : d.mostrados + ' evento(s) registrado(s) neste alerta.'));
            var roll = el('div', 'rolagem'), t = el('table');
            roll.appendChild(t); caixa.appendChild(roll);
            tabela(t, [{ k: 'quando', t: 'Hora' }, { k: 'metodo', t: 'Método' }, { k: 'caminho', t: 'Caminho', cls: 'quebra' },
                { k: 'status', t: 'Status' }, { k: 'host', t: 'Host', cls: 'nowrap' }, { k: 'ua', t: 'User-Agent', cls: 'quebra' }, { k: 'outros', t: 'Outros', cls: 'quebra' }],
                d.eventos, { vazio: 'O CrowdSec não guardou os eventos deste alerta.', ordenar: false });
            var det = el('details', 'bruto'), sm = el('summary', '', 'JSON bruto do alerta (como a API do CrowdSec devolveu)');
            det.appendChild(sm); det.appendChild(el('pre', '', d.bruto));
            caixa.appendChild(det);
        }).catch(function (e) { if (e.message !== 'sessao') { limpa(caixa); caixa.appendChild(el('p', 'erro', 'Sem conexão com o painel.')); } });
    }

    // ------------------------------------------------------------ aba: visão geral
    var COLS_REINC = [{ k: 'ip', t: 'IP', ip: 1 }, { k: 'pais', t: 'País' }, { k: 'as', t: 'Rede (AS)' }, { k: 'alertas', t: 'Alertas', num: 1 },
        { k: 'cenarios', t: 'Cenários', fmt: function (v) { return (v || []).map(semPrefixo).join(', '); } }, { k: 'ultimo', t: 'Último' },
        { k: 'banido', t: 'Bloqueio', fmt: function (v) { return v ? 'em vigor' : 'expirado'; } }];

    // "+32% vs. período anterior" sob o cartão; nada quando não há base de comparação
    function variacao(c, completo) {
        if (!c) return null;
        var t;
        if (c.pct === null || c.pct === undefined) t = c.atual ? 'novo (antes: 0)' : '';
        else t = (c.pct > 0 ? '+' : '') + c.pct + '% vs. período anterior';
        if (!t) return null;
        if (completo === false) t += ' (aprox.)';
        var e = el('div', 'var ' + (c.pct > 0 ? 'sobe' : c.pct < 0 ? 'desce' : ''), t);
        e.title = 'Período anterior, de mesma duração: ' + fmt(c.anterior);
        return e;
    }

    function idade(s) {
        if (s < 90) return 'há instantes';
        if (s < 5400) return 'há ' + Math.round(s / 60) + ' min';
        if (s < 172800) return 'há ' + Math.round(s / 3600) + ' h';
        return 'há ' + Math.round(s / 86400) + ' dias';
    }

    // faixa de destaque: pico recente de alertas; sem pico, só a idade do último alerta
    function pico(a, ultimo) {
        var b = $('pico');
        limpa(b);
        b.className = 'pico' + (a ? ' alto' : '');
        if (a) {
            b.appendChild(el('strong', '', 'Pico de alertas: '));
            b.appendChild(el('span', '', a.n + ' alertas em ' + a.quando + ', ' + a.fator + '× a média do período (' + a.media + '). Confira os IPs e cenários abaixo.'));
        } else {
            b.appendChild(el('span', '', 'Sem picos fora do normal. Último alerta: ' + (ultimo === null || ultimo === undefined ? 'nenhum no período' : idade(ultimo)) + '.'));
        }
        b.hidden = false;
    }

    function carregarGeral(usuario) {
        return api('/api/resumo?janela=' + janela(), usuario).then(function (x) {
            if (!x.ok) { aviso(x.d.erro || 'Falha ao carregar os dados.'); return; }
            var d = x.d;
            aviso('');
            var cp = d.comparativo, cc = d.comparativo_completo;
            kpis($('kpis'), [['Bloqueios ativos', d.kpis.bans], ['Alertas no período', d.kpis.alertas, '', variacao(cp && cp.alertas, cc)],
                ['IPs distintos', d.kpis.ips, '', variacao(cp && cp.ips, cc)], ['Países', d.kpis.paises],
                ['Eventos suspeitos', d.kpis.eventos, 'Soma dos eventos dos alertas. Clique num alerta para ver cada um.', variacao(cp && cp.eventos, cc)]]);
            pico(d.anomalia, d.ultimo_alerta_ha_s);
            $('passo').textContent = d.passo;
            grafico(d.serie);
            rosca(d.top_cenarios);
            barras('top-cen', d.top_cenarios, 'cenarios'); barras('top-pais', d.top_paises); barras('top-ip', d.top_ips); barras('top-as', d.top_as);
            barras('top-dom', d.dominios || []);
            $('n-dom').textContent = d.dominios_ok ? '(pelos eventos guardados)' : '';
            if (!d.dominios_ok) {
                var bd = $('top-dom');
                limpa(bd);
                bd.appendChild(el('div', 'vazio', 'A API do CrowdSec não devolveu os eventos dos alertas; abra um alerta para ver o site atingido.'));
            }
            barras('funil', d.funil);
            $('n-reinc').textContent = '(' + d.n_reincidentes + ' IP(s) com 2 ou mais alertas no período' +
                (d.n_reincidentes > d.reincidentes.length ? '; mostrando os ' + d.reincidentes.length + ' que mais voltaram' : '') + ')';
            tabela($('t-reinc'), COLS_REINC, d.reincidentes, { vazio: 'Nenhum IP voltou mais de uma vez neste período.', ordem: 'alertas' });
            var longo = janela() !== '1h';
            $('card-mapa').hidden = !longo;
            if (longo) mapaCalor(d.mapa);
            $('n-bans').textContent = '(' + d.bans.length + ')';
            tabela($('t-bans'), COLS_BANS, d.bans, { vazio: 'Nenhum bloqueio ativo.', id: 'alerta', ordem: 'expira' });
            tabela($('t-alertas'), COLS_ALERTAS, d.alertas, { vazio: 'Nenhum alerta no período.', id: 'id', ordem: 'quando' });
            atualizado(d.gerado_em);
        }).catch(falha);
    }

    // ------------------------------------------------------------ aba: alertas
    function filtrarAlertas() {
        var q = $('a-q').value.trim().toLowerCase(), cen = $('a-cen').value, pais = $('a-pais').value;
        var l = estado.alertas.filter(function (a) {
            return (!cen || a.cenario === cen) && (!pais || a.pais === pais) &&
                (!q || (a.ip + ' ' + a.cenario + ' ' + a.pais + ' ' + a.as).toLowerCase().indexOf(q) >= 0);
        });
        $('n-alertas').textContent = fmt(l.length) + ' de ' + fmt(estado.alertas.length) + ' alertas' +
            (estado.alertas.length >= 3000 ? ' (só os 3.000 mais recentes aparecem aqui; reduza o período)' : '');
        tabela($('t-alertas-full'), COLS_ALERTAS, l, { vazio: 'Nenhum alerta com esses filtros.', id: 'id', ordem: 'quando', limite: 1000 });
    }

    function carregarAlertas(usuario) {
        $('csv-alertas').href = BASE + '/api/alertas.csv?janela=' + janela();
        return api('/api/alertas?janela=' + janela(), usuario).then(function (x) {
            if (!x.ok) { aviso(x.d.erro || 'Falha ao carregar os alertas.'); return; }
            aviso('');
            estado.alertas = x.d.alertas;
            preencherSelect($('a-cen'), x.d.cenarios, 'Todos os cenários', semPrefixo);
            preencherSelect($('a-pais'), x.d.paises, 'Todos os países');
            filtrarAlertas();
            atualizado(x.d.gerado_em);
        }).catch(falha);
    }

    // ------------------------------------------------------------ aba: bloqueios
    function contar(lista, k) {
        var c = {};
        lista.forEach(function (b) { c[b[k] || '—'] = (c[b[k] || '—'] || 0) + 1; });
        return Object.keys(c).sort(function (a, b) { return c[b] - c[a]; }).map(function (n) { return [n, c[n]]; });
    }

    function colsBloqueios() {
        if (!estado.pode) return COLS_BANS;
        return COLS_BANS.concat([{ k: 'liberar', t: '', botao: function (b) {
            var bt = el('button', 'botao pequeno', 'Liberar');
            bt.type = 'button';
            bt.addEventListener('click', function (ev) { ev.stopPropagation(); liberarIp(b.ip); });
            return bt;
        } }]);
    }

    function filtrarBloqueios() {
        var q = $('b-q').value.trim().toLowerCase(), tipo = $('b-tipo').value, origem = $('b-origem').value;
        var l = estado.bans.filter(function (b) {
            return (!tipo || b.tipo === tipo) && (!origem || b.origem === origem) &&
                (!q || (b.ip + ' ' + b.cenario + ' ' + b.pais + ' ' + b.as).toLowerCase().indexOf(q) >= 0);
        });
        $('n-bloq').textContent = fmt(l.length) + ' de ' + fmt(estado.bans.length) + ' bloqueios em vigor';
        tabela($('t-bloqueios'), colsBloqueios(), l, { vazio: 'Nenhum bloqueio em vigor.', id: 'alerta', ordem: 'expira' });
    }

    function carregarBloqueios(usuario) {
        return api('/api/bloqueios', usuario).then(function (x) {
            if (!x.ok) { aviso(x.d.erro || 'Falha ao carregar os bloqueios.'); return; }
            aviso('');
            estado.bans = x.d.bans;
            estado.pode = !!x.d.pode_liberar;
            $('b-liberar').hidden = !estado.pode;
            carregarLiberacoes();
            var tipos = contar(x.d.bans, 'tipo'), origens = contar(x.d.bans, 'origem');
            kpis($('b-kpis'), [['Bloqueios em vigor', x.d.bans.length]]
                .concat(tipos.slice(0, 2).map(function (p) { return ['Ação: ' + p[0], p[1]]; }))
                .concat(origens.slice(0, 3).map(function (p) { return ['Origem: ' + p[0], p[1]]; })));
            preencherSelect($('b-tipo'), tipos.map(function (p) { return p[0]; }), 'Todas as ações');
            preencherSelect($('b-origem'), origens.map(function (p) { return p[0]; }), 'Todas as origens');
            $('csv-bloqueios').href = BASE + '/api/bloqueios.csv';
            filtrarBloqueios();
            atualizado(x.d.gerado_em);
        }).catch(falha);
    }

    // ------------------------------------------------------------ liberar IP (a única ação de escrita do painel)
    function postJson(caminho, corpo) {
        return fetch(BASE + caminho, { method: 'POST', credentials: 'same-origin',
            headers: { 'Content-Type': 'application/json', 'X-Atividade': '1' }, body: JSON.stringify(corpo) })
            .then(function (r) {
                if (r.status === 401) { location.href = BASE + '/login'; throw new Error('sessao'); }
                return r.json().then(function (d) { return { ok: r.ok, status: r.status, d: d }; });
            });
    }

    function carregarLiberacoes() {
        return api('/api/liberacoes', false).then(function (x) {
            if (!x.ok) return;
            $('n-lib').textContent = !x.d.ativo ? 'A liberação de IPs ainda não foi ativada neste servidor.'
                : (x.d.itens.length ? 'As ' + x.d.itens.length + ' mais recentes.' : 'Nenhuma liberação registrada ainda.');
            tabela($('t-liberacoes'), [{ k: 'quando', t: 'Quando', ord: 't' }, { k: 'usuario', t: 'Quem liberou' }, { k: 'alvo', t: 'IP', ip: 1 },
                { k: 'motivo', t: 'Motivo', cls: 'quebra' }, { k: 'removidos', t: 'Bloqueios removidos', num: 1 }, { k: 'resultado', t: 'Resultado' },
                { k: 'ip_origem', t: 'De onde', ip: 1 }], x.d.itens, { ordenar: false, vazio: 'Nenhuma liberação registrada.' });
        }).catch(function () { /* o histórico é um extra: sem ele a página segue */ });
    }

    function liberarIp(ip) {
        var m = $('modal');
        limpa(m);
        m.hidden = false;
        var caixa = el('div', 'caixa caixa-peq');
        m.appendChild(caixa);
        var cab = el('div', 'caixa-cab');
        cab.appendChild(el('h2', '', 'Liberar IP'));
        var fecha = el('button', 'fechar', 'Cancelar');
        fecha.type = 'button';
        fecha.addEventListener('click', fechar);
        cab.appendChild(fecha);
        caixa.appendChild(cab);
        caixa.appendChild(el('p', 'nota', 'Remove os bloqueios em vigor deste IP, em todos os sites e portas do servidor. A liberação fica registrada com o seu nome.'));
        var f = el('form', 'form-lib');
        function campo(rotulo, id, tipo, valor, max) {
            var l = el('label', 'rot-lib', rotulo);
            l.setAttribute('for', id);
            f.appendChild(l);
            var i = el('input', 'campo-lib');
            i.id = id; i.type = tipo; i.maxLength = max; i.autocomplete = 'off'; i.required = true;
            if (valor) i.value = valor;
            f.appendChild(i);
            return i;
        }
        var cip = campo('IP a liberar', 'lib-ip-m', 'text', ip, 45);
        var cmo = campo('Motivo (fica registrado)', 'lib-motivo', 'text', '', 200);
        var csn = campo('Senha de liberação', 'lib-senha', 'password', '', 200);
        csn.autocomplete = 'new-password';
        var msg = el('p', 'erro', '');
        msg.hidden = true;
        msg.setAttribute('role', 'alert');
        f.appendChild(msg);
        var ok = el('p', 'ok-lib', '');
        ok.hidden = true;
        f.appendChild(ok);
        var go = el('button', 'botao', 'Liberar IP');
        go.type = 'submit';
        f.appendChild(go);
        f.addEventListener('submit', function (ev) {
            ev.preventDefault();
            msg.hidden = true;
            go.disabled = true;
            postJson('/api/liberar', { ip: cip.value, motivo: cmo.value, senha: csn.value }).then(function (x) {
                csn.value = '';
                if (!x.ok) { msg.textContent = x.d.erro || 'Não foi possível liberar.'; msg.hidden = false; go.disabled = false; return; }
                ok.textContent = x.d.removidos ? 'Pronto: ' + x.d.removidos + ' bloqueio(s) de ' + x.d.ip + ' removido(s).'
                    : 'Nenhum bloqueio em vigor para ' + x.d.ip + ': não havia o que remover.';
                ok.hidden = false;
                go.hidden = true;
                fecha.textContent = 'Fechar';
                carregarBloqueios(true);
            }).catch(function (e) {
                if (e.message !== 'sessao') { msg.textContent = 'Sem conexão com o painel.'; msg.hidden = false; go.disabled = false; }
            });
        });
        caixa.appendChild(f);
        (ip ? cmo : cip).focus();
    }

    // ------------------------------------------------------------ aba: consultar IP
    function consultarIp(ip) {
        $('ip-q').value = ip;
        var res = $('ip-res');
        limpa(res);
        res.appendChild(el('p', 'vazio', 'Consultando…'));
        api('/api/ip?ip=' + encodeURIComponent(ip), true).then(function (x) {
            limpa(res);
            if (!x.ok) { res.appendChild(el('p', 'erro', x.d.erro || 'Falha na consulta.')); return; }
            var d = x.d;
            var k = el('section', 'kpis');
            res.appendChild(k);
            kpis(k, [['Alertas', d.total_alertas], ['Eventos', d.total_eventos], ['País', d.pais || '—'], ['Primeiro alerta', d.primeiro || '—'], ['Último alerta', d.ultimo || '—']]);
            var c1 = el('section', 'cartao larg');
            c1.appendChild(el('h2', '', 'Rede e decisões para ' + d.ip));
            c1.appendChild(el('p', 'nota', 'Rede (AS): ' + (d.as || 'não informada')));
            if (d.pode_liberar) {
                var lb = el('button', 'botao', 'Liberar este IP…');
                lb.type = 'button';
                lb.addEventListener('click', function () { liberarIp(d.ip); });
                c1.appendChild(lb);
            }
            if (!d.decisoes_consultadas) {
                c1.appendChild(el('p', 'nota', 'As decisões em vigor não foram consultadas (falta a chave de bouncer no servidor); veja os bloqueios ativos na aba Bloqueios.'));
            } else if (!d.decisoes.length) {
                c1.appendChild(el('p', 'nota', 'Nenhuma decisão em vigor para este endereço (nem na lista da comunidade).'));
            } else {
                var r1 = el('div', 'rolagem'), t1 = el('table');
                r1.appendChild(t1); c1.appendChild(r1);
                tabela(t1, [{ k: 'tipo', t: 'Ação', glos: 'acoes' }, { k: 'origem', t: 'Origem', glos: 'origens' }, { k: 'escopo', t: 'Escopo' }, { k: 'valor', t: 'Valor', ip: 1 },
                    { k: 'cenario', t: 'Motivo', fmt: semPrefixo, cen: 1 }, { k: 'expira', t: 'Expira em', dir: 1 }], d.decisoes, { ordenar: false });
            }
            res.appendChild(c1);
            var c2 = el('section', 'cartao');
            c2.appendChild(el('h2', '', 'Cenários acionados'));
            var b = el('div', 'barras');
            b.id = 'ip-cen';
            c2.appendChild(b);
            res.appendChild(c2);
            barras('ip-cen', d.cenarios, 'cenarios');
            if (d.serie_dias && d.serie_dias.length > 1) {
                var c4 = el('section', 'cartao dois');
                c4.appendChild(el('h2', '', 'Linha do tempo (alertas por dia)'));
                var g4 = el('div', '');
                g4.id = 'ip-serie';
                c4.appendChild(g4);
                res.appendChild(c4);
                grafico(d.serie_dias, 'ip-serie');
            }
            if (d.sites && d.sites.length) {
                var c5 = el('section', 'cartao');
                c5.appendChild(el('h2', '', 'Sites atingidos (eventos)'));
                var b5 = el('div', 'barras');
                b5.id = 'ip-sites';
                c5.appendChild(b5);
                res.appendChild(c5);
                barras('ip-sites', d.sites);
            }
            var c3 = el('section', 'cartao larg');
            c3.appendChild(el('h2', '', 'Alertas deste IP'));
            var r3 = el('div', 'rolagem alta'), t3 = el('table');
            r3.appendChild(t3); c3.appendChild(r3);
            res.appendChild(c3);
            tabela(t3, COLS_ALERTAS, d.alertas, { vazio: 'O CrowdSec não tem alertas para este endereço.', id: 'id', ordem: 'quando' });
        }).catch(function (e) { if (e.message !== 'sessao') { limpa(res); res.appendChild(el('p', 'erro', 'Sem conexão com o painel.')); } });
    }

    // ------------------------------------------------------------ aba: cenários
    function carregarCenarios(usuario) {
        return api('/api/cenarios?janela=' + janela(), usuario).then(function (x) {
            if (!x.ok) { aviso(x.d.erro || 'Falha ao carregar os cenários.'); return; }
            aviso('');
            var l = x.d.cenarios, inst = l.filter(function (c) { return c.instalado; }).length, disp = l.filter(function (c) { return c.alertas > 0; }).length;
            $('cen-nota').textContent = inst + ' cenários instalados; ' + disp + ' dispararam no período. ' +
                (x.d.hub_legivel ? '' : 'As descrições dos cenários do hub não estão visíveis: o painel não tem leitura em /etc/crowdsec/hub (veja a documentação). ') +
                (x.d.metricas ? '' : 'Contadores do motor indisponíveis.');
            tabela($('t-cenarios'), [{ k: 'nome', t: 'Cenário', cen: 1 }, { k: 'alertas', t: 'Alertas', num: 1 }, { k: 'ips', t: 'IPs', num: 1 },
                { k: 'eventos', t: 'Eventos', num: 1 }, { k: 'ultimo', t: 'Último' }, { k: 'pais_top', t: 'País' },
                { k: 'overflow', t: 'Disparos (motor)', num: 1 }, { k: 'origem', t: 'Origem' }, { k: 'tipo', t: 'Tipo' },
                { k: 'capacidade', t: 'Capacidade' }, { k: 'leakspeed', t: 'Leakspeed' }, { k: 'blackhole', t: 'Blackhole' },
                { k: 'descricao', t: 'Descrição', cls: 'quebra' }], l, { ordem: 'alertas', vazio: 'Sem cenários.' });
            atualizado(new Date().toLocaleTimeString('pt-BR'));
        }).catch(falha);
    }

    // ------------------------------------------------------------ aba: saúde
    function carregarSaude(usuario) {
        return api('/api/saude', usuario).then(function (x) {
            if (!x.ok) { aviso(x.d.erro || 'Falha ao carregar a saúde do CrowdSec.'); return; }
            aviso('');
            var d = x.d;
            var rec = Object.keys(d.recursos).map(function (r) { return r + (d.recursos[r] ? ' ✓' : ' ✗'); }).join(' · ');
            kpis($('s-kpis'), [['Versão', d.versao || '—'], ['Lista da comunidade (CAPI)', d.capi ? d.capi.quando + ' (' + fmtHa(d.capi.ha_s) + ')' : 'nunca atualizada'],
                ['Console / PAPI', d.papi ? d.papi.quando : 'host não inscrito no Console'], ['Cenários em memória', d.buckets_ativos],
                ['Recursos', rec || '—']]);
            var mr = d.recente_minutos, sufixo = mr ? ' (últimos ' + mr + ' min)' : ' (coletando…)';
            var pct = function (v) { return v === null || v === undefined ? '—' : String(v).replace('.', ',') + '%'; };
            var num = function (v) { return v === null || v === undefined ? '—' : fmt(v); };
            $('s-nota').textContent = 'Os totais são acumulados desde que o CrowdSec iniciou (um erro do início continua somado até o próximo reinício). ' +
                'As colunas "últimos min" mostram só o que mudou no período; o painel mede uma vez por minuto e recomeça a medir se for reiniciado.';
            tabela($('s-fontes'), [{ k: 'nome', t: 'Fonte' }, { k: 'tipo', t: 'Tipo' }, { k: 'lidas', t: 'Linhas lidas (total)', num: 1 }, { k: 'ok', t: 'Interpretadas (total)', num: 1 },
                { k: 'ko', t: 'Não interpretadas (total)', num: 1 }, { k: 'pct_ok', t: '% ok (total)', dir: 1, fmt: pct },
                { k: 'r_lidas', t: 'Linhas' + sufixo, num: 1, fmt: num }, { k: 'r_ko', t: 'Falhas' + sufixo, num: 1, fmt: num },
                { k: 'r_pct', t: '% ok' + sufixo, dir: 1, fmt: pct },
                { k: 'whitelist', t: 'Ignoradas (whitelist)', num: 1 }], d.fontes, { ordem: 'lidas', vazio: 'Nenhuma fonte de log ativa.' });
            tabela($('s-cen'), [{ k: 'nome', t: 'Cenário', cen: 1 }, { k: 'instanciados', t: 'Criados', num: 1 }, { k: 'despejados', t: 'Eventos recebidos', num: 1 },
                { k: 'overflow', t: 'Disparos', num: 1 }, { k: 'underflow', t: 'Expiraram sem disparar', num: 1 }, { k: 'ativos', t: 'Em memória agora', num: 1 }],
                d.cenarios, { ordem: 'overflow', vazio: 'Nenhum cenário recebeu eventos ainda.' });
            tabela($('s-dec'), [{ k: 'acao', t: 'Ação', glos: 'acoes' }, { k: 'origem', t: 'Origem', glos: 'origens' }, { k: 'motivo', t: 'Motivo', cen: 1 }, { k: 'n', t: 'Decisões', num: 1 }],
                d.decisoes, { ordem: 'n', vazio: 'Nenhuma decisão em vigor.' });
            tabela($('s-parsers'), [{ k: 'nome', t: 'Parser' }, { k: 'estagio', t: 'Estágio' }, { k: 'hits', t: 'Linhas', num: 1 }, { k: 'ok', t: 'Ok', num: 1 }, { k: 'ko', t: 'Falhas', num: 1 }],
                d.parsers, { ordem: 'hits', vazio: 'Sem dados.' });
            tabela($('s-wl'), [{ k: 'nome', t: 'Whitelist' }, { k: 'motivo', t: 'Motivo' }, { k: 'hits', t: 'Linhas ignoradas', num: 1 }], d.whitelists, { ordem: 'hits', vazio: 'Nenhuma whitelist acionada.' });
            tabela($('s-lapi'), [{ k: 'method', t: 'Método' }, { k: 'route', t: 'Rota', cls: 'q' }, { k: 'n', t: 'Requisições', num: 1 }], d.lapi_rotas, { ordem: 'n', vazio: 'Sem dados.' });
            tabela($('s-maq'), [{ k: 'maquina', t: 'Máquina', cls: 'q' }, { k: 'method', t: 'Método' }, { k: 'route', t: 'Rota', cls: 'q' }, { k: 'n', t: 'Req.', num: 1 }], d.lapi_maquinas, { ordem: 'n', vazio: 'Sem dados.' });
            tabela($('s-bou'), [{ k: 'bouncer', t: 'Bouncer', cls: 'q' }, { k: 'route', t: 'Rota', cls: 'q' }, { k: 'n', t: 'Req.', num: 1 }], d.lapi_bouncers, { ordem: 'n', vazio: 'Nenhum bouncer consultou a API.' });
            tabela($('s-hb'), [{ k: 'maquina', t: 'Máquina' }, { k: 'quando', t: 'Último' }, { k: 'ha_s', t: 'Há', dir: 1, fmt: function (v) { return fmtHa(v); } }],
                d.heartbeat, { ordenar: false, vazio: 'Sem heartbeat.' });
            atualizado(new Date().toLocaleTimeString('pt-BR'));
        }).catch(falha);
    }

    // ------------------------------------------------------------ aba: configuração
    function blocoItens(box, itens, vazio) {
        var r = el('div', 'rolagem'), t = el('table');
        r.appendChild(t); box.appendChild(r);
        tabela(t, [{ k: 'nome', t: 'Nome' }, { k: 'origem', t: 'Origem' }, { k: 'descricao', t: 'Descrição', cls: 'quebra' }], itens, { ordem: 'nome', asc: true, vazio: vazio });
    }

    function carregarConfig(usuario) {
        return api('/api/config', usuario).then(function (x) {
            if (!x.ok) { aviso(x.d.erro || 'Falha ao ler a configuração.'); return; }
            aviso('');
            var d = x.d, acq = $('c-acq');
            limpa(acq);
            if (!d.acquisicao.length) acq.appendChild(el('p', 'vazio', 'Nenhum arquivo de aquisição legível.'));
            d.acquisicao.forEach(function (a) { acq.appendChild(el('h3', '', a.arquivo)); acq.appendChild(el('pre', '', a.conteudo)); });
            tabela($('c-col'), [{ k: 'nome', t: 'Coleção' }, { k: 'origem', t: 'Origem' }, { k: 'descricao', t: 'Descrição', cls: 'quebra' }], d.colecoes, { ordem: 'nome', asc: true, vazio: 'Nenhuma coleção.' });
            ['c-par', 'c-pos'].forEach(function (id, i) {
                var box = $(id);
                limpa(box);
                var est = i === 0 ? d.parsers : d.postoverflows;
                if (!est.length) box.appendChild(el('p', 'vazio', 'Nada instalado.'));
                est.forEach(function (e) { box.appendChild(el('h3', '', e.estagio)); blocoItens(box, e.itens, 'Vazio.'); });
            });
            atualizado(new Date().toLocaleTimeString('pt-BR'));
        }).catch(falha);
    }

    // ------------------------------------------------------------ abas
    var CARREGADORES = { geral: carregarGeral, alertas: carregarAlertas, bloqueios: carregarBloqueios, ip: null,
        cenarios: carregarCenarios, saude: carregarSaude, config: carregarConfig };
    var COM_PERIODO = ['geral', 'alertas', 'cenarios'];

    function mostrar(nome, usuario) {
        if (!Object.prototype.hasOwnProperty.call(CARREGADORES, nome)) nome = 'geral';
        aba = nome;
        Array.prototype.forEach.call(document.querySelectorAll('.aba'), function (s) { s.hidden = s.id !== 'aba-' + nome; });
        Array.prototype.forEach.call(document.querySelectorAll('#abas button'), function (b) { b.className = b.getAttribute('data-aba') === nome ? 'ativa' : ''; });
        $('janela').parentNode.hidden = COM_PERIODO.indexOf(nome) < 0;
        try { history.replaceState(null, '', '#' + nome); } catch (e) { /* sem histórico: segue sem o hash */ }
        aviso('');
        if (CARREGADORES[nome]) CARREGADORES[nome](usuario);
    }

    // ------------------------------------------------------------ eventos
    ['click', 'keydown'].forEach(function (ev) { document.addEventListener(ev, function () { atividade = true; }, { passive: true }); });
    document.addEventListener('keydown', function (ev) { if (ev.key === 'Escape') fechar(); });
    $('modal').addEventListener('click', function (ev) { if (ev.target === $('modal')) fechar(); });
    Array.prototype.forEach.call(document.querySelectorAll('#abas button'), function (b) {
        b.addEventListener('click', function () { mostrar(b.getAttribute('data-aba'), true); });
    });
    $('janela').addEventListener('change', function () { if (CARREGADORES[aba]) CARREGADORES[aba](true); });
    ['a-q', 'a-cen', 'a-pais'].forEach(function (id) { $(id).addEventListener(id === 'a-q' ? 'input' : 'change', filtrarAlertas); });
    ['b-q', 'b-tipo', 'b-origem'].forEach(function (id) { $(id).addEventListener(id === 'b-q' ? 'input' : 'change', filtrarBloqueios); });
    $('form-liberar').addEventListener('submit', function (ev) {
        ev.preventDefault();
        liberarIp($('lib-ip').value.trim());
    });
    $('form-ip').addEventListener('submit', function (ev) {
        ev.preventDefault();
        var v = $('ip-q').value.trim();
        if (v) consultarIp(v);
    });

    dicaEl = el('div', 'dica');
    dicaEl.setAttribute('role', 'tooltip');
    dicaEl.hidden = true;
    document.body.appendChild(dicaEl);
    document.addEventListener('mouseover', function (ev) {
        var a = ev.target.closest ? ev.target.closest('.glos') : null;
        if (!a) return;
        clearTimeout(dicaTimer);
        if (a !== dicaAlvo) dicaTimer = setTimeout(function () { mostrarDica(a); }, 180);
    });
    document.addEventListener('mouseout', function (ev) {
        var a = ev.target.closest ? ev.target.closest('.glos') : null;
        if (!a || (ev.relatedTarget && a.contains(ev.relatedTarget))) return;
        clearTimeout(dicaTimer);
        dicaTimer = setTimeout(esconderDica, 120);
    });
    document.addEventListener('focusin', function (ev) { if (ev.target.classList && ev.target.classList.contains('glos')) mostrarDica(ev.target); });
    document.addEventListener('focusout', esconderDica);
    document.addEventListener('scroll', esconderDica, true);
    document.addEventListener('click', function (ev) {  // toque: não há "passar o mouse"
        var a = ev.target.closest ? ev.target.closest('.glos') : null;
        if (a && window.matchMedia && !window.matchMedia('(hover: hover)').matches) mostrarDica(a);
        else if (!a) esconderDica();
    });
    document.addEventListener('keydown', function (ev) { if (ev.key === 'Escape') esconderDica(); });

    mostrar((location.hash || '').slice(1), false);
    timerAtualizacao = setInterval(function () { if (aba !== 'ip' && aba !== 'config' && CARREGADORES[aba]) CARREGADORES[aba](false); }, 30000);
})();
