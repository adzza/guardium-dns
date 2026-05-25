// Guardium DNS - Alpine.js component.
//
// Two views:
//   - "family" (default): people-first parent-friendly UI.
//   - "techie": the original device-level dashboard.
//
// State, data fetching, Chart.js rendering, and small UI helpers all live
// here. Keep the API surface narrow: the HTML calls the methods on this
// object, never poking at internals directly.

function getCookie(name) {
  return document.cookie.split('; ').reduce((acc, c) => {
    const [k, v] = c.split('=');
    return k === name ? decodeURIComponent(v || '') : acc;
  }, '');
}

const PROFILE_THEME = {
  'unrestricted': {chip: 'bg-slate-500/15 text-slate-300 ring-slate-400/30',
                   active: 'bg-slate-500/30 text-slate-100 ring-slate-300/40',
                   gradient: 'bg-gradient-to-br from-slate-700/80 to-slate-600/40',
                   tone:    'text-slate-300'},
  'default':      {chip: 'bg-blue-500/15 text-blue-300 ring-blue-400/30',
                   active: 'bg-blue-500/30 text-blue-50 ring-blue-300/40',
                   gradient: 'bg-gradient-to-br from-blue-600/60 to-sky-500/30',
                   tone:    'text-blue-300'},
  'kids':         {chip: 'bg-pink-500/15 text-pink-300 ring-pink-400/30',
                   active: 'bg-pink-500/30 text-pink-50 ring-pink-300/40',
                   gradient: 'bg-gradient-to-br from-pink-500/60 to-fuchsia-500/30',
                   tone:    'text-pink-300'},
  'no-youtube':   {chip: 'bg-red-500/15 text-red-300 ring-red-400/30',
                   active: 'bg-red-500/30 text-red-50 ring-red-300/40',
                   gradient: 'bg-gradient-to-br from-red-500/60 to-rose-600/30',
                   tone:    'text-red-300'},
  'no-streaming': {chip: 'bg-purple-500/15 text-purple-300 ring-purple-400/30',
                   active: 'bg-purple-500/30 text-purple-50 ring-purple-300/40',
                   gradient: 'bg-gradient-to-br from-purple-600/60 to-violet-500/30',
                   tone:    'text-purple-300'},
  'no-gaming':    {chip: 'bg-amber-500/15 text-amber-300 ring-amber-400/30',
                   active: 'bg-amber-500/30 text-amber-50 ring-amber-300/40',
                   gradient: 'bg-gradient-to-br from-amber-500/60 to-orange-500/30',
                   tone:    'text-amber-300'},
  'internet-off': {chip: 'bg-rose-500/15 text-rose-300 ring-rose-400/30',
                   active: 'bg-rose-500/30 text-rose-50 ring-rose-300/40',
                   gradient: 'bg-gradient-to-br from-rose-600/70 to-rose-500/40',
                   tone:    'text-rose-300'},
};
const NO_PROFILE_THEME = {chip: 'bg-slate-700/40 text-slate-300 ring-white/5',
                          active: 'bg-slate-700 text-slate-100 ring-white/10',
                          gradient: 'bg-gradient-to-br from-slate-800 to-slate-900',
                          tone:    'text-slate-300'};

const PERSON_GRADIENTS = {
  indigo:  'bg-gradient-to-br from-indigo-500/60 to-violet-500/30',
  sky:     'bg-gradient-to-br from-sky-500/60 to-cyan-500/30',
  emerald: 'bg-gradient-to-br from-emerald-500/60 to-teal-500/30',
  amber:   'bg-gradient-to-br from-amber-500/60 to-orange-500/30',
  rose:    'bg-gradient-to-br from-rose-500/60 to-pink-500/30',
  pink:    'bg-gradient-to-br from-pink-500/60 to-fuchsia-500/30',
  purple:  'bg-gradient-to-br from-purple-500/60 to-fuchsia-500/30',
};

window.dashboard = function () {
  return {
    // ---------------------------------------------------------------- state
    view: localStorage.getItem('dnsdash:view') || 'family',
    tab: 'overview',
    timeRange: 'LastHour',
    loading: false,
    error: null,
    user: null,

    stats: {},
    devices: [],
    favourites: [],
    distribution: [],
    topDomains: [],
    topBlocked: [],
    profiles: [],
    audit: [],
    people: [],
    schedules: [],
    quotas: [],
    familyPause: null,
    serverTime: null,
    today: '',

    mainChartData: null,
    mainChart: null,

    deviceFilter: '',
    showAllUnassigned: false,

    inspector: {open: false, loading: false, device: null, entries: [],
                totalEntries: 0, blockedInPage: 0},
    personDrawer: {open: false, person: null},
    personEditor: {open: false, id: null, name: '', avatar: '🧒',
                    color: 'indigo', baseProfileId: null},
    scheduleDrawer: {open: false, id: null, targetKind: 'person', targetId: null,
                      name: '', weekdayMask: 0x7F, startMin: 21*60, endMin: 7*60,
                      profileId: null, enabled: true},
    quotaDrawer: {open: false, id: null, targetKind: 'person', targetId: null,
                   weekdayMask: 0x7F, minutesMax: 120,
                   profileWhenExceeded: null, enabled: true},
    familyPauseDialog: {open: false, minutes: 30, excludePersonIds: []},
    assignDrawer: {open: false, device: null},
    diagnose: {open: false, loading: false, ip: null, label: null, data: null},

    settings: {
      router: {
        // Vendor selector: 'asus' | 'unifi' | 'none'. Drives which
        // sub-form is rendered and which API fields are validated.
        vendor: 'none',
        // Capabilities of the active adapter (populated from
        // /api/router/capabilities); used to grey out stages the
        // vendor doesn't support.
        capabilities: null,
        // ASUS fields (existing).
        host: '', username: '', passwordInput: '', passwordSet: false,
        scheme: 'http', port: null, enabled: false,
        // Stage 2 - DNS Director (ASUS)
        dnsDirectorEnabled: false, dnsDirectorIp: '',
        // Stage 3 - SSH + DoH blocklist (ASUS)
        sshEnabled: false, sshPort: 2222,
        sshPasswordInput: '', sshPasswordSet: false,
        dohBlockEnabled: false,
        // UniFi fields (alpha).
        unifi: {
          host: '', username: '', site: 'default',
          passwordInput: '', passwordSet: false,
          apiKeyInput: '', apiKeySet: false,
          verifyTls: false,
          dohBlockEnabled: false,
        },
      },
      routerLoaded: false,
      routerSaving: false,
      routerTesting: false,
      routerTestResult: null,
      routerClients: null,
      routerClientsError: null,
      routerClientsLoading: false,
      sshTesting: false,
      sshTestResult: null,
      applying: false,
      applyResult: null,
    },

    // ------------------------------------------------------------- lifecycle

    async init() {
      this.user = getCookie('dnsdash_user') || null;
      try {
        await this.loadProfiles();
        await this.refresh();
      } catch (e) {
        this.error = e.message || String(e);
      }
      setInterval(() => this.refresh({silent: true}), 30000);
    },

    setView(v) {
      this.view = v;
      localStorage.setItem('dnsdash:view', v);
    },

    // ------------------------------------------------------------- styling

    tabClass(t) {
      const base = 'px-3 py-1.5 rounded-lg text-sm';
      return this.tab === t
        ? base + ' bg-indigo-500/20 ring-1 ring-indigo-400/40 text-indigo-100'
        : base + ' hover:bg-white/5 text-slate-300';
    },
    bottomNavClass(t) {
      const base = 'flex flex-col items-center justify-center py-2.5 transition active:scale-95';
      return this.tab === t ? base + ' text-indigo-300' : base + ' text-slate-400';
    },

    profileEmoji(id) { if (!id) return '·'; const p = this.profiles.find(x => x.id === id); return p ? p.emoji : '•'; },
    profileLabel(id) { if (!id) return null; const p = this.profiles.find(x => x.id === id); return p ? p.label : id; },
    profileShortLabel(id) { if (!id) return ''; const p = this.profiles.find(x => x.id === id); return p ? (p.short || p.label) : id; },
    profileChip(id)        { return (PROFILE_THEME[id] || NO_PROFILE_THEME).chip; },
    profileChipActive(id)  { return (PROFILE_THEME[id] || NO_PROFILE_THEME).active; },
    profileGradient(id)    { return (PROFILE_THEME[id] || NO_PROFILE_THEME).gradient; },
    profileTone(id)        { return (PROFILE_THEME[id] || NO_PROFILE_THEME).tone; },

    auditChip(action) {
      const a = (action || '').toLowerCase();
      if (a.includes('login')) return 'bg-sky-500/15 text-sky-300 ring-sky-400/30';
      if (a.includes('logout')) return 'bg-slate-500/15 text-slate-300 ring-slate-400/30';
      if (a.includes('clear')) return 'bg-amber-500/15 text-amber-300 ring-amber-400/30';
      if (a.includes('rename') || a.includes('adopt')) return 'bg-indigo-500/15 text-indigo-300 ring-indigo-400/30';
      if (a.includes('favourite') || a.includes('unfavourite')) return 'bg-yellow-500/15 text-yellow-300 ring-yellow-400/30';
      if (a.includes('pause') || a.includes('resume')) return 'bg-rose-500/15 text-rose-300 ring-rose-400/30';
      if (a.includes('person')) return 'bg-purple-500/15 text-purple-300 ring-purple-400/30';
      if (a.includes('schedule') || a.includes('quota')) return 'bg-cyan-500/15 text-cyan-300 ring-cyan-400/30';
      if (a.includes('set-profile')) return 'bg-emerald-500/15 text-emerald-300 ring-emerald-400/30';
      return 'bg-slate-500/15 text-slate-300 ring-slate-400/30';
    },

    timeRangeLabel() {
      return ({
        'LastHour': 'Last hour (per-minute)',
        'LastDay':  'Last 24 hours (per-hour)',
        'LastWeek': 'Last 7 days (per-day)',
        'LastMonth':'Last 31 days (per-day)',
      })[this.timeRange] || this.timeRange;
    },

    // ------------------------------------------------------------- effective

    effectiveLabel(eff) {
      if (!eff) return 'Unknown';
      if (eff.profileId === 'internet-off') return 'Internet off';
      if (eff.profileId) return this.profileLabel(eff.profileId);
      return 'No profile';
    },
    effectiveEmoji(eff) {
      if (!eff) return '·';
      if (eff.profileId === 'internet-off') return '⛔';
      if (eff.profileId) return this.profileEmoji(eff.profileId);
      return '·';
    },
    effectiveChip(eff) {
      if (!eff || !eff.profileId) return 'bg-slate-700/40 text-slate-300 ring-white/5';
      return PROFILE_THEME[eff.profileId]?.chip || 'bg-slate-700/40 text-slate-300 ring-white/5';
    },
    effectiveSourceShort(eff) {
      if (!eff) return '—';
      const src = eff.source || 'base';
      const labels = {base:'profile', manual:'paused', schedule:'schedule',
                       quota:'limit', 'family-pause':'family', 'no-profile':'—'};
      return (labels[src] || src) + (eff.profileId ? ': ' + this.profileLabel(eff.profileId) : '');
    },

    // ----------------------------------------------------------------- data

    async loadProfiles() {
      const r = await this.api('/api/profiles');
      this.profiles = r.profiles || [];
    },

    async refresh({silent = false} = {}) {
      if (!silent) this.loading = true;
      this.error = null;
      try {
        const data = await this.api(`/api/overview?time_range=${encodeURIComponent(this.timeRange)}`);
        this.stats = data.stats || {};
        this.devices = data.devices || [];
        this.favourites = data.favourites || [];
        this.distribution = data.distribution || [];
        this.topDomains = data.topDomains || [];
        this.topBlocked = data.topBlockedDomains || [];
        this.people = data.people || [];
        this.schedules = data.schedules || [];
        this.quotas = data.quotas || [];
        this.familyPause = data.familyPause || null;
        this.serverTime = data.serverTime || null;
        this.today = data.today || '';
        this.mainChartData = data.mainChartData || null;
        // Refresh the open person drawer with new data.
        if (this.personDrawer.open && this.personDrawer.person) {
          const fresh = this.people.find(p => p.id === this.personDrawer.person.id);
          if (fresh) this.personDrawer.person = fresh;
          else this.closePerson();
        }
        this.$nextTick(() => this.renderMainChart());
        if (this.tab === 'audit') await this.loadAudit();
      } catch (e) {
        this.error = e.message || String(e);
      } finally {
        this.loading = false;
      }
    },

    async loadAudit() {
      try { const r = await this.api('/api/audit'); this.audit = r.entries || []; }
      catch (_) { /* soft */ }
    },

    // -------------------------------------------------------- KPIs (techie)

    kpis() {
      const s = this.stats || {};
      const total = s.totalQueries || 0;
      const blocked = s.totalBlocked || 0;
      const blockedPct = total ? ((blocked / total) * 100).toFixed(1) + '%' : '—';
      const onlineNow = this.devices.filter(d => d.online).length;
      return [
        {k:'q', icon:'📊', label:'Queries',   value:this.formatNum(total),                sub:this.timeRangeLabel(),     tone:'text-slate-100'},
        {k:'b', icon:'🚫', label:'Blocked',   value:this.formatNum(blocked),              sub:blockedPct + ' of total', tone:'text-rose-300'},
        {k:'n', icon:'❓', label:'NXDomain',  value:this.formatNum(s.totalNxDomain || 0), sub:'no such domain',         tone:'text-slate-300'},
        {k:'c', icon:'👥', label:'Clients',   value:this.formatNum(s.totalClients || 0),  sub:`${onlineNow} online now`,tone:'text-emerald-300'},
        {k:'cache', icon:'⚡', label:'Cache', value:this.formatNum(s.totalCached || 0),   sub:'served from cache',      tone:'text-sky-300'},
        {k:'rec', icon:'🌐', label:'Recursive', value:this.formatNum(s.totalRecursive || 0), sub:'forwarded',           tone:'text-indigo-300'},
      ];
    },

    distributionView() {
      const profileOrder = this.profiles.map(p => p.id);
      const buckets = (this.distribution || []).map(b => {
        const isNoProfile = b.profileId === null && !b.groupName;
        const isExternal = !!b.external;
        const meta = b.profileId ? this.profiles.find(p => p.id === b.profileId) : null;
        return {
          key: b.profileId || ('grp-' + b.groupName) || 'none',
          profileId: b.profileId,
          groupName: b.groupName,
          emoji: meta ? meta.emoji : (isNoProfile ? '·' : '🗂️'),
          label: meta ? meta.label : (isNoProfile ? 'No profile' : b.groupName),
          subtitle: isNoProfile
            ? 'fall through to catch-all'
            : (meta ? `profile: ${b.profileId}` : `external group: ${b.groupName}`),
          tone: this.profileTone(b.profileId),
          count: b.count,
          devices: b.devices || [],
          sortKey: isNoProfile ? 1000 : (isExternal ? 500 + b.count : profileOrder.indexOf(b.profileId)),
        };
      });
      buckets.sort((a, b) => a.sortKey - b.sortKey);
      return buckets;
    },

    totalAssigned() {
      return (this.distribution || [])
        .filter(b => b.profileId || b.groupName)
        .reduce((acc, b) => acc + (b.count || 0), 0);
    },

    // -------------------------------------------------------- family helpers

    onlineCount() { return this.devices.filter(d => d.online).length; },
    totalDevices() { return this.devices.length; },

    todayLabel() {
      const ts = this.serverTime ? new Date(this.serverTime * 1000) : new Date();
      return ts.toLocaleDateString(undefined, {weekday: 'long'}) + ' · '
        + ts.toLocaleTimeString(undefined, {hour: 'numeric', minute: '2-digit'});
    },

    weatherLine() {
      // Friendly one-liner based on what's currently going on.
      if (this.familyPause) return 'Family pause is on';
      const liveBlocked = this.devices.filter(d =>
        d.effective && (d.effective.profileId === 'internet-off')).length;
      const scheduled = this.devices.filter(d =>
        d.effective && d.effective.source === 'schedule').length;
      if (liveBlocked > 0) return `${liveBlocked} device${liveBlocked===1?'':'s'} currently locked down`;
      if (scheduled > 0) return `${scheduled} device${scheduled===1?'':'s'} on a schedule`;
      const total = this.stats.totalBlocked || 0;
      return total ? `${this.formatNum(total)} blocked queries today` : 'Quiet right now';
    },

    unassignedDevices() {
      // Only devices with no person AND no direct profile - the genuinely
      // untouched ones that need attention. Profile-assigned-only devices
      // surface in the Devices card grid below the People grid.
      return this.devices.filter(d => !d.personId && !d.baseProfileId)
        .sort((a, b) => (b.online - a.online) || (b.hits - a.hits));
    },

    // Devices that have a base profile but no person, grouped by profile.
    // Displayed as a card grid mirroring the People grid.
    devicesByProfile() {
      const groups = new Map();
      for (const d of this.devices) {
        if (d.personId || !d.baseProfileId) continue;
        const arr = groups.get(d.baseProfileId) || [];
        arr.push(d);
        groups.set(d.baseProfileId, arr);
      }
      // Preserve the canonical profile order (more permissive -> more strict).
      const order = this.profiles.map(p => p.id);
      return order
        .filter(pid => groups.has(pid))
        .map(pid => {
          const devices = groups.get(pid).sort((a, b) =>
            (b.online - a.online) || this.displayName(a).localeCompare(this.displayName(b)));
          return {
            profile: this.profiles.find(p => p.id === pid),
            devices,
            onlineCount: devices.filter(d => d.online).length,
          };
        });
    },

    personGradient(p) {
      return PERSON_GRADIENTS[p.color] || PERSON_GRADIENTS.indigo;
    },
    personInitials(p) {
      if (!p || !p.name) return '?';
      return p.name.split(/\s+/).slice(0, 2).map(s => s[0] || '').join('').toUpperCase();
    },

    primaryQuota(p) {
      // Pick the quota that applies to today's weekday, smallest budget wins.
      const dow = new Date().getDay();
      const idx = dow === 0 ? 6 : dow - 1; // JS Sun=0 -> our Mon=0
      const candidates = (p.quotas || []).filter(q => q.enabled && (q.weekdayMask & (1 << idx)));
      if (!candidates.length) return null;
      candidates.sort((a, b) => a.minutesMax - b.minutesMax);
      return candidates[0];
    },

    quotaPct(p) {
      const q = this.primaryQuota(p);
      if (!q) return 0;
      return Math.round((p.todayMinutes / q.minutesMax) * 100);
    },
    quotaPctLabel(p) {
      const q = this.primaryQuota(p);
      if (!q) return '';
      const pct = this.quotaPct(p);
      if (pct >= 100) return 'Done';
      return pct + '%';
    },
    quotaBar(p) {
      const pct = this.quotaPct(p);
      if (pct >= 100) return 'bg-rose-500';
      if (pct >= 80)  return 'bg-amber-400';
      return 'bg-emerald-500';
    },
    quotaToneText(p) {
      const pct = this.quotaPct(p);
      if (pct >= 100) return 'text-rose-300';
      if (pct >= 80)  return 'text-amber-300';
      return 'text-emerald-300';
    },
    quotaBarFor(q, used) {
      const pct = (used / q.minutesMax) * 100;
      if (pct >= 100) return 'bg-rose-500';
      if (pct >= 80)  return 'bg-amber-400';
      return 'bg-emerald-500';
    },

    activeScheduleFor(p) {
      // Returns the schedule (if any) currently active for the person. Used for
      // the "Bedtime until 7am" chip on person cards.
      const now = new Date();
      const minNow = now.getHours() * 60 + now.getMinutes();
      const dow = now.getDay();
      const idx = dow === 0 ? 6 : dow - 1;
      for (const s of (p.schedules || [])) {
        if (!s.enabled) continue;
        const dayActive = s.weekdayMask & (1 << idx);
        if (s.startMin < s.endMin) {
          if (dayActive && minNow >= s.startMin && minNow < s.endMin) return s;
        } else if (s.startMin > s.endMin) {
          // overnight wrap
          const yesterdayIdx = (idx + 6) % 7;
          if (dayActive && minNow >= s.startMin) return s;
          if ((s.weekdayMask & (1 << yesterdayIdx)) && minNow < s.endMin) return s;
        }
      }
      return null;
    },

    // ------------------------------------------------------- formatting helpers

    formatNum(n) {
      if (n == null) return '—';
      n = Number(n);
      if (n >= 1_000_000) return (n/1_000_000).toFixed(1) + 'M';
      if (n >= 10_000)    return (n/1_000).toFixed(1) + 'k';
      return n.toLocaleString();
    },
    formatTs(ts) { if (!ts) return '—'; return new Date(ts * 1000).toLocaleString(); },
    relTime(ts) {
      if (!ts) return '—';
      const diff = Math.floor(Date.now()/1000) - ts;
      if (diff < 60)    return diff + 's ago';
      if (diff < 3600)  return Math.floor(diff/60) + 'm ago';
      if (diff < 86400) return Math.floor(diff/3600) + 'h ago';
      return Math.floor(diff/86400) + 'd ago';
    },
    formatTime(ts) {
      if (!ts) return '';
      try { return new Date(ts).toLocaleTimeString(undefined, {hour: 'numeric', minute: '2-digit'}); }
      catch { return ts; }
    },
    formatHM(min) {
      const h = Math.floor((min || 0) / 60);
      const m = (min || 0) % 60;
      const ampm = h >= 12 ? 'pm' : 'am';
      const hh = ((h + 11) % 12) + 1;
      return `${hh}:${m.toString().padStart(2,'0')}${ampm}`;
    },
    formatMinutes(m) {
      m = Math.max(0, Math.round(m || 0));
      if (m < 60) return m + 'm';
      const h = Math.floor(m / 60);
      const rem = m % 60;
      if (rem === 0) return h + 'h';
      return `${h}h ${rem}m`;
    },
    minToHHMM(m) {
      m = m || 0;
      const h = Math.floor(m / 60);
      const mm = m % 60;
      return `${h.toString().padStart(2,'0')}:${mm.toString().padStart(2,'0')}`;
    },
    hhmmToMin(s) {
      const m = (s || '').split(':');
      return (parseInt(m[0]||'0',10)*60) + parseInt(m[1]||'0',10);
    },
    weekdayLabel(mask) {
      const d = ['Mon','Tue','Wed','Thu','Fri','Sat','Sun'];
      const on = d.filter((_, i) => mask & (1 << i));
      if (on.length === 7) return 'Every day';
      if (on.length === 5 && !on.includes('Sat') && !on.includes('Sun')) return 'Weekdays';
      if (on.length === 2 && on.includes('Sat') && on.includes('Sun')) return 'Weekends';
      return on.join(' ');
    },
    remainingMinutes(epoch) {
      if (!epoch) return '0m';
      const now = Math.floor(Date.now() / 1000);
      return this.formatMinutes(Math.max(0, Math.floor((epoch - now) / 60)));
    },
    formatAnswer(a) {
      if (!a) return '—';
      if (Array.isArray(a)) return a.map(x => typeof x === 'object' ? (x.rData || JSON.stringify(x)) : x).join(', ');
      return typeof a === 'object' ? JSON.stringify(a) : String(a);
    },
    rcodeClass(rcode) {
      if (!rcode) return 'bg-slate-500/15 text-slate-300 ring-slate-400/30';
      const r = rcode.toLowerCase();
      if (r === 'noerror')  return 'bg-emerald-500/15 text-emerald-300 ring-emerald-400/30';
      if (r === 'nxdomain') return 'bg-rose-500/15 text-rose-300 ring-rose-400/30';
      if (r === 'refused')  return 'bg-amber-500/15 text-amber-300 ring-amber-400/30';
      return 'bg-slate-500/15 text-slate-300 ring-slate-400/30';
    },
    displayName(d) { return d?.label || d?.hostname || d?.ip || ''; },
    subtitle(d) {
      const parts = [];
      if (d.label && d.hostname && d.label.toLowerCase() !== d.hostname.toLowerCase()) parts.push(d.hostname);
      if (d.label || d.hostname) parts.push(d.ip);
      if (!parts.length) parts.push(d.online ? 'online' : 'last seen ' + this.relTime(d.lastSeen));
      return parts.join(' · ');
    },
    filteredDevices() {
      const f = (this.deviceFilter || '').trim().toLowerCase();
      if (!f) return this.devices;
      return this.devices.filter(d =>
        (d.label && d.label.toLowerCase().includes(f)) ||
        (d.hostname && d.hostname.toLowerCase().includes(f)) ||
        d.ip.toLowerCase().includes(f) ||
        (d.profileId && d.profileId.toLowerCase().includes(f))
      );
    },

    // ------------------------------------------------------------ device API

    async setDeviceBaseProfile(d, profileId) {
      try {
        await this.api(`/api/devices/${encodeURIComponent(d.ip)}/profile`, {
          method: 'POST',
          body: JSON.stringify({profileId: profileId || null}),
        });
        await this.refresh({silent:true});
      } catch (e) { this.error = e.message; await this.refresh({silent:true}); }
    },

    async quickKill(d) {
      // In family/techie views, "quick kill" is a manual pause until end-of-day.
      const eff = d.effective || {};
      if (eff.source === 'manual') {
        await this.resumeDevice(d);
        return;
      }
      try {
        await this.api(`/api/devices/${encodeURIComponent(d.ip)}/pause`, {
          method: 'POST',
          body: JSON.stringify({minutes: 12*60, profileId: null, note: 'quick off'}),
        });
        await this.refresh({silent:true});
      } catch (e) { this.error = e.message; }
    },

    async resumeDevice(d) {
      try {
        await this.api(`/api/devices/${encodeURIComponent(d.ip)}/resume`, {method: 'POST'});
        await this.refresh({silent:true});
      } catch (e) { this.error = e.message; }
    },

    async toggleFavourite(d) {
      const next = !d.favourite;
      try {
        await this.api(`/api/devices/${encodeURIComponent(d.ip)}/favourite`, {
          method: 'POST', body: JSON.stringify({favourite: next}),
        });
        d.favourite = next;
        this.refresh({silent:true});
      } catch (e) { this.error = e.message; }
    },

    async renameDevice(d, label) {
      const trimmed = (label || '').trim();
      try {
        await this.api(`/api/devices/${encodeURIComponent(d.ip)}`, {
          method: 'POST', body: JSON.stringify({label: trimmed || null}),
        });
        d.label = trimmed || null;
      } catch (e) { this.error = e.message; }
    },

    async adoptHostname(d) {
      try {
        const r = await this.api(`/api/devices/${encodeURIComponent(d.ip)}/adopt-hostname`, {method: 'POST'});
        d.label = r.label;
      } catch (e) { this.error = e.message; }
    },

    async adoptAllHostnames() {
      const targets = this.devices.filter(d => d.hostname && !d.label);
      if (!targets.length) {
        this.error = 'No devices with PTR hostnames to adopt.';
        setTimeout(() => this.error = null, 3000);
        return;
      }
      for (const d of targets) {
        try {
          const r = await this.api(`/api/devices/${encodeURIComponent(d.ip)}/adopt-hostname`, {method: 'POST'});
          d.label = r.label;
        } catch (_) { /* ignore */ }
      }
    },

    async refreshHostnames() {
      try {
        await this.api('/api/hostnames/refresh', {method: 'POST'});
        await this.refresh({silent: true});
      } catch (e) { this.error = e.message; }
    },

    async identifyDevice(d) {
      // Force-refresh OUI vendor + DNS-pattern device-type hint for
      // a single device. Patches the local row in place so the user
      // sees the change without a full reload.
      d._identifying = true;
      try {
        const r = await this.api(`/api/devices/${encodeURIComponent(d.ip)}/identify`, {method: 'POST'});
        d.vendor = r.vendor;
        d.fingerprintHint = r.fingerprintHint;
        d.macAddress = r.macAddress || d.macAddress;
      } catch (e) {
        this.error = e.message;
      } finally {
        d._identifying = false;
      }
    },

    fingerprintLabel(d) {
      // Compose the inline fingerprint suffix shown beneath the IP.
      // Returns '' when nothing is known so the wrapper x-show resolves
      // to false.
      const hint = d.fingerprintHint;
      const vendor = d.vendor;
      if (hint && vendor) return `${hint} · ${vendor}`;
      return hint || vendor || '';
    },

    async logout() {
      try { await this.api('/api/auth/logout', {method: 'POST'}); } catch (_) {}
      window.location.href = '/login';
    },

    // ----------------------------------------------------------------- people

    async attachToPerson(d, personIdRaw) {
      const personId = personIdRaw ? Number(personIdRaw) : null;
      try {
        await this.api(`/api/devices/${encodeURIComponent(d.ip)}/person`, {
          method: 'POST', body: JSON.stringify({personId}),
        });
        await this.refresh({silent: true});
      } catch (e) { this.error = e.message; }
    },

    detachDevice(ip) { this.attachToPerson({ip}, null); },

    // -------------------------------------------------------- assign drawer

    openAssign(d) {
      this.assignDrawer.open = true;
      this.assignDrawer.device = d;
    },
    closeAssign() {
      this.assignDrawer.open = false;
      this.assignDrawer.device = null;
    },

    async assignDevicePerson(personId) {
      const d = this.assignDrawer.device;
      if (!d) return;
      try {
        // Picking a person clears any device-level base profile so the
        // person's profile is the single source of truth.
        if (d.baseProfileId) {
          await this.api(`/api/devices/${encodeURIComponent(d.ip)}/profile`, {
            method: 'POST', body: JSON.stringify({profileId: null}),
          });
        }
        await this.api(`/api/devices/${encodeURIComponent(d.ip)}/person`, {
          method: 'POST', body: JSON.stringify({personId: Number(personId)}),
        });
        this.closeAssign();
        await this.refresh({silent: true});
      } catch (e) { this.error = e.message; }
    },

    async assignDeviceProfile(profileId) {
      const d = this.assignDrawer.device;
      if (!d) return;
      try {
        // Picking a profile detaches from any person (this device has its own
        // rules now). Cleaner mental model than "person + override".
        if (d.personId) {
          await this.api(`/api/devices/${encodeURIComponent(d.ip)}/person`, {
            method: 'POST', body: JSON.stringify({personId: null}),
          });
        }
        await this.api(`/api/devices/${encodeURIComponent(d.ip)}/profile`, {
          method: 'POST', body: JSON.stringify({profileId}),
        });
        this.closeAssign();
        await this.refresh({silent: true});
      } catch (e) { this.error = e.message; }
    },

    async clearAssignment() {
      const d = this.assignDrawer.device;
      if (!d) return;
      try {
        if (d.personId) {
          await this.api(`/api/devices/${encodeURIComponent(d.ip)}/person`, {
            method: 'POST', body: JSON.stringify({personId: null}),
          });
        }
        if (d.baseProfileId) {
          await this.api(`/api/devices/${encodeURIComponent(d.ip)}/profile`, {
            method: 'POST', body: JSON.stringify({profileId: null}),
          });
        }
        this.closeAssign();
        await this.refresh({silent: true});
      } catch (e) { this.error = e.message; }
    },

    openPerson(p) {
      this.personDrawer.open = true;
      this.personDrawer.person = p;
    },
    closePerson() {
      this.personDrawer.open = false;
      this.personDrawer.person = null;
    },

    openCreatePerson() {
      this.personEditor.open = true;
      this.personEditor.id = null;
      this.personEditor.name = '';
      this.personEditor.avatar = '🧒';
      this.personEditor.color = 'indigo';
      this.personEditor.baseProfileId = null;
    },
    editPerson(p) {
      this.personEditor.open = true;
      this.personEditor.id = p.id;
      this.personEditor.name = p.name;
      this.personEditor.avatar = p.avatar || '🧒';
      this.personEditor.color = p.color || 'indigo';
      this.personEditor.baseProfileId = p.baseProfileId || null;
    },
    closePersonEditor() { this.personEditor.open = false; },

    async savePerson() {
      const name = (this.personEditor.name || '').trim();
      if (!name) { this.error = 'Name is required'; return; }
      const body = {
        name,
        avatar: this.personEditor.avatar || null,
        color:  this.personEditor.color || null,
        baseProfileId: this.personEditor.baseProfileId || null,
      };
      try {
        if (this.personEditor.id) {
          await this.api(`/api/people/${this.personEditor.id}`, {method:'PATCH', body: JSON.stringify(body)});
        } else {
          await this.api('/api/people', {method:'POST', body: JSON.stringify(body)});
        }
        this.closePersonEditor();
        await this.refresh({silent:true});
      } catch (e) { this.error = e.message; }
    },

    async deletePerson() {
      if (!this.personEditor.id) return;
      if (!confirm('Delete this person? Their devices will become unassigned.')) return;
      try {
        await this.api(`/api/people/${this.personEditor.id}`, {method:'DELETE'});
        this.closePersonEditor();
        this.closePerson();
        await this.refresh({silent:true});
      } catch (e) { this.error = e.message; }
    },

    async setPersonProfile(p, profileId) {
      try {
        await this.api(`/api/people/${p.id}`, {
          method:'PATCH', body: JSON.stringify({baseProfileId: profileId}),
        });
        await this.refresh({silent:true});
      } catch (e) { this.error = e.message; }
    },

    async quickPausePerson(p, minutes) {
      try {
        await this.api(`/api/people/${p.id}/pause`, {
          method:'POST', body: JSON.stringify({minutes, profileId: null}),
        });
        await this.refresh({silent:true});
      } catch (e) { this.error = e.message; }
    },

    async endOfDayPerson(p) {
      const minsLeft = this.minutesUntilLocalMidnight();
      try {
        await this.api(`/api/people/${p.id}/pause`, {
          method:'POST',
          body: JSON.stringify({minutes: minsLeft, profileId: null, note: 'until tomorrow'}),
        });
        await this.refresh({silent:true});
      } catch (e) { this.error = e.message; }
    },

    async resumePerson(p) {
      try {
        await this.api(`/api/people/${p.id}/resume`, {method:'POST'});
        await this.refresh({silent:true});
      } catch (e) { this.error = e.message; }
    },

    minutesUntilLocalMidnight() {
      const now = new Date();
      const tomorrow = new Date(now.getFullYear(), now.getMonth(), now.getDate() + 1);
      return Math.max(1, Math.floor((tomorrow - now) / 60000));
    },

    // -------------------------------------------------------- family pause

    openFamilyPause() {
      this.familyPauseDialog.open = true;
      this.familyPauseDialog.minutes = 30;
      this.familyPauseDialog.excludePersonIds = [];
    },

    toggleFamilyPauseExclude(pid) {
      const ix = this.familyPauseDialog.excludePersonIds.indexOf(pid);
      if (ix >= 0) this.familyPauseDialog.excludePersonIds.splice(ix, 1);
      else this.familyPauseDialog.excludePersonIds.push(pid);
    },

    async confirmFamilyPause() {
      try {
        await this.api('/api/family/pause', {
          method:'POST',
          body: JSON.stringify({
            minutes: this.familyPauseDialog.minutes,
            profileId: null,
            excludePersonIds: this.familyPauseDialog.excludePersonIds,
            note: 'family pause',
          }),
        });
        this.familyPauseDialog.open = false;
        await this.refresh({silent:true});
      } catch (e) { this.error = e.message; }
    },

    async resumeFamily() {
      try {
        await this.api('/api/family/resume', {method:'POST'});
        await this.refresh({silent:true});
      } catch (e) { this.error = e.message; }
    },

    // -------------------------------------------------------- schedules CRUD

    openScheduleEditor(s, targetKind, targetId) {
      this.scheduleDrawer.open = true;
      this.scheduleDrawer.targetKind = targetKind;
      this.scheduleDrawer.targetId = targetId ? String(targetId) : null;
      if (s) {
        this.scheduleDrawer.id = s.id;
        this.scheduleDrawer.name = s.name || '';
        this.scheduleDrawer.weekdayMask = s.weekdayMask;
        this.scheduleDrawer.startMin = s.startMin;
        this.scheduleDrawer.endMin = s.endMin;
        this.scheduleDrawer.profileId = s.profileId || null;
        this.scheduleDrawer.enabled = s.enabled;
      } else {
        this.scheduleDrawer.id = null;
        this.scheduleDrawer.name = '';
        this.scheduleDrawer.weekdayMask = 0x7F;
        this.scheduleDrawer.startMin = 21 * 60;
        this.scheduleDrawer.endMin = 7 * 60;
        this.scheduleDrawer.profileId = null;
        this.scheduleDrawer.enabled = true;
      }
    },
    closeScheduleEditor() { this.scheduleDrawer.open = false; },
    scheduleScopeLabel() {
      const tk = this.scheduleDrawer.targetKind;
      if (tk === 'all') return 'Applies to everyone';
      if (tk === 'person') {
        const p = this.people.find(x => String(x.id) === this.scheduleDrawer.targetId);
        return p ? `For ${p.name}` : 'For person';
      }
      return `For device ${this.scheduleDrawer.targetId || ''}`;
    },
    toggleScheduleWeekday(i) { this.scheduleDrawer.weekdayMask ^= (1 << i); },
    setScheduleWeekdays(mask) { this.scheduleDrawer.weekdayMask = mask; },

    async saveSchedule() {
      const body = {
        name: this.scheduleDrawer.name || null,
        weekdayMask: this.scheduleDrawer.weekdayMask,
        startMin: this.scheduleDrawer.startMin,
        endMin: this.scheduleDrawer.endMin,
        profileId: this.scheduleDrawer.profileId || null,
        enabled: this.scheduleDrawer.enabled,
      };
      try {
        if (this.scheduleDrawer.id) {
          await this.api(`/api/schedules/${this.scheduleDrawer.id}`, {method:'PATCH', body: JSON.stringify(body)});
        } else {
          await this.api('/api/schedules', {method:'POST', body: JSON.stringify({
            ...body,
            targetKind: this.scheduleDrawer.targetKind,
            targetId: this.scheduleDrawer.targetId,
          })});
        }
        this.closeScheduleEditor();
        await this.refresh({silent:true});
      } catch (e) { this.error = e.message; }
    },

    async deleteSchedule(s) {
      if (!s || !s.id) return;
      if (!confirm('Delete this schedule?')) return;
      try {
        await this.api(`/api/schedules/${s.id}`, {method:'DELETE'});
        this.closeScheduleEditor();
        await this.refresh({silent:true});
      } catch (e) { this.error = e.message; }
    },

    async toggleSchedule(s) {
      try {
        await this.api(`/api/schedules/${s.id}`, {method:'PATCH', body: JSON.stringify({enabled: !s.enabled})});
        await this.refresh({silent:true});
      } catch (e) { this.error = e.message; }
    },

    async addSchedulePreset(person, kind) {
      const presets = {
        bedtime:      {name: 'Bedtime',       weekdayMask: 0x7F, startMin: 21*60,    endMin: 7*60,  profileId: null},
        school:       {name: 'School hours',  weekdayMask: 0x1F, startMin: 9*60,     endMin: 15*60, profileId: 'no-streaming'},
        beforeSchool: {name: 'Before school', weekdayMask: 0x1F, startMin: 6*60,     endMin: 9*60,  profileId: null},
        afterSchool:  {name: 'After school',  weekdayMask: 0x1F, startMin: 15*60+30, endMin: 21*60, profileId: null},
        dinner:       {name: 'Dinner',        weekdayMask: 0x7F, startMin: 18*60,    endMin: 19*60, profileId: null},
      };
      const preset = presets[kind];
      if (!preset) return;
      try {
        await this.api('/api/schedules', {method:'POST', body: JSON.stringify({
          targetKind: 'person', targetId: String(person.id),
          ...preset, enabled: true,
        })});
        await this.refresh({silent:true});
      } catch (e) { this.error = e.message; }
    },

    // ----------------------------------------------------------- quotas CRUD

    openQuotaEditor(q, targetKind, targetId) {
      this.quotaDrawer.open = true;
      this.quotaDrawer.targetKind = targetKind;
      this.quotaDrawer.targetId = targetId ? String(targetId) : null;
      if (q) {
        this.quotaDrawer.id = q.id;
        this.quotaDrawer.weekdayMask = q.weekdayMask;
        this.quotaDrawer.minutesMax = q.minutesMax;
        this.quotaDrawer.profileWhenExceeded = q.profileWhenExceeded || null;
        this.quotaDrawer.enabled = q.enabled;
      } else {
        this.quotaDrawer.id = null;
        this.quotaDrawer.weekdayMask = 0x7F;
        this.quotaDrawer.minutesMax = 120;
        this.quotaDrawer.profileWhenExceeded = null;
        this.quotaDrawer.enabled = true;
      }
    },
    closeQuotaEditor() { this.quotaDrawer.open = false; },
    quotaScopeLabel() {
      if (this.quotaDrawer.targetKind === 'person') {
        const p = this.people.find(x => String(x.id) === this.quotaDrawer.targetId);
        return p ? `For ${p.name}` : 'For person';
      }
      return `For device ${this.quotaDrawer.targetId || ''}`;
    },
    toggleQuotaWeekday(i) { this.quotaDrawer.weekdayMask ^= (1 << i); },
    setQuotaWeekdays(mask) { this.quotaDrawer.weekdayMask = mask; },

    async saveQuota() {
      const body = {
        weekdayMask: this.quotaDrawer.weekdayMask,
        minutesMax: this.quotaDrawer.minutesMax,
        profileWhenExceeded: this.quotaDrawer.profileWhenExceeded || null,
        enabled: this.quotaDrawer.enabled,
      };
      try {
        if (this.quotaDrawer.id) {
          await this.api(`/api/quotas/${this.quotaDrawer.id}`, {method:'PATCH', body: JSON.stringify(body)});
        } else {
          await this.api('/api/quotas', {method:'POST', body: JSON.stringify({
            ...body,
            targetKind: this.quotaDrawer.targetKind,
            targetId: this.quotaDrawer.targetId,
          })});
        }
        this.closeQuotaEditor();
        await this.refresh({silent:true});
      } catch (e) { this.error = e.message; }
    },

    async deleteQuota(q) {
      if (!q || !q.id) return;
      if (!confirm('Delete this daily limit?')) return;
      try {
        await this.api(`/api/quotas/${q.id}`, {method:'DELETE'});
        this.closeQuotaEditor();
        await this.refresh({silent:true});
      } catch (e) { this.error = e.message; }
    },

    async toggleQuota(q) {
      try {
        await this.api(`/api/quotas/${q.id}`, {method:'PATCH', body: JSON.stringify({enabled: !q.enabled})});
        await this.refresh({silent:true});
      } catch (e) { this.error = e.message; }
    },

    // ---------------------------------------------------------- diagnose

    async openDiagnose(d) {
      this.diagnose.open = true;
      this.diagnose.loading = true;
      this.diagnose.ip = d.ip;
      this.diagnose.label = this.displayName(d);
      this.diagnose.data = null;
      try {
        this.diagnose.data = await this.api(
          `/api/devices/${encodeURIComponent(d.ip)}/diagnose`);
      } catch (e) {
        this.error = e.message;
      } finally {
        this.diagnose.loading = false;
      }
    },
    closeDiagnose() { this.diagnose.open = false; this.diagnose.data = null; },
    async refreshDiagnose() {
      if (!this.diagnose.ip) return;
      this.diagnose.loading = true;
      try {
        this.diagnose.data = await this.api(
          `/api/devices/${encodeURIComponent(this.diagnose.ip)}/diagnose`);
      } catch (e) { this.error = e.message; }
      finally { this.diagnose.loading = false; }
    },
    diagnoseChip(status) {
      switch (status) {
        case 'active':
          return 'bg-emerald-500/15 text-emerald-300 ring-emerald-400/30';
        case 'untested':
        case 'untested-category':
          return 'bg-amber-500/15 text-amber-300 ring-amber-400/30';
        case 'warning':
          return 'bg-rose-500/15 text-rose-300 ring-rose-400/30';
        default:
          return 'bg-slate-500/15 text-slate-300 ring-slate-400/30';
      }
    },
    diagnoseEmoji(status) {
      switch (status) {
        case 'active': return '✓';
        case 'untested':
        case 'untested-category': return '◔';
        case 'warning': return '⚠';
        default: return '·';
      }
    },

    // ---------------------------------------------------------------- settings

    async openSettings() {
      this.tab = 'settings';
      if (!this.settings.routerLoaded) {
        await this.loadRouterSettings();
      }
    },

    _absorbRouterCfg(cfg) {
      this.settings.router.vendor = cfg.vendor || 'none';
      this.settings.router.capabilities = cfg.capabilities || null;
      this.settings.router.host = cfg.host || '';
      this.settings.router.username = cfg.username || '';
      this.settings.router.scheme = cfg.scheme || 'http';
      this.settings.router.port = cfg.port || null;
      this.settings.router.enabled = !!cfg.enabled;
      this.settings.router.passwordSet = !!cfg.passwordSet;
      this.settings.router.dnsDirectorEnabled = !!cfg.dnsDirectorEnabled;
      this.settings.router.dnsDirectorIp = cfg.dnsDirectorIp || '';
      this.settings.router.sshEnabled = !!cfg.sshEnabled;
      this.settings.router.sshPort = cfg.sshPort || 2222;
      this.settings.router.sshPasswordSet = !!cfg.sshPasswordSet;
      this.settings.router.dohBlockEnabled = !!cfg.dohBlockEnabled;
      const u = cfg.unifi || {};
      this.settings.router.unifi.host = u.host || '';
      this.settings.router.unifi.username = u.username || '';
      this.settings.router.unifi.site = u.site || 'default';
      this.settings.router.unifi.verifyTls = !!u.verifyTls;
      this.settings.router.unifi.passwordSet = !!u.passwordSet;
      this.settings.router.unifi.apiKeySet = !!u.apiKeySet;
      this.settings.router.unifi.dohBlockEnabled = !!u.dohBlockEnabled;
    },

    async loadRouterSettings() {
      try {
        const r = await this.api('/api/settings/router');
        this._absorbRouterCfg(r.router || {});
        this.settings.router.passwordInput = '';
        this.settings.router.sshPasswordInput = '';
        this.settings.router.unifi.passwordInput = '';
        this.settings.router.unifi.apiKeyInput = '';
        this.settings.routerLoaded = true;
        if (this.settings.router.vendor === 'asus'
            && this.settings.router.enabled
            && this.settings.router.passwordSet) {
          this.loadRouterClients();
        }
      } catch (e) {
        this.error = e.message;
      }
    },

    async saveRouter() {
      this.settings.routerSaving = true;
      this.settings.routerTestResult = null;
      try {
        const body = {
          vendor: this.settings.router.vendor || 'none',
          // ASUS fields are always included so toggling vendor doesn't
          // wipe them out; the server only persists what changes.
          host: this.settings.router.host || '',
          username: this.settings.router.username || '',
          scheme: this.settings.router.scheme || 'http',
          port: this.settings.router.port || null,
          enabled: !!this.settings.router.enabled,
          dnsDirectorEnabled: !!this.settings.router.dnsDirectorEnabled,
          dnsDirectorIp: this.settings.router.dnsDirectorIp || '',
          sshEnabled: !!this.settings.router.sshEnabled,
          sshPort: this.settings.router.sshPort || 2222,
          dohBlockEnabled: !!this.settings.router.dohBlockEnabled,
        };
        // ASUS passwords: send only when user typed something (or
        // explicitly empty to clear).
        const pwd = this.settings.router.passwordInput;
        if (pwd && pwd.length) body.password = pwd;
        const sshPwd = this.settings.router.sshPasswordInput;
        if (sshPwd && sshPwd.length) body.sshPassword = sshPwd;

        // UniFi sub-block.
        const u = this.settings.router.unifi;
        body.unifi = {
          host: u.host || '',
          username: u.username || '',
          site: u.site || 'default',
          verifyTls: !!u.verifyTls,
          dohBlockEnabled: !!u.dohBlockEnabled,
        };
        if (u.passwordInput && u.passwordInput.length) {
          body.unifi.password = u.passwordInput;
        }
        if (u.apiKeyInput && u.apiKeyInput.length) {
          body.unifi.apiKey = u.apiKeyInput;
        }

        const r = await this.api('/api/settings/router',
          {method: 'PUT', body: JSON.stringify(body)});
        this._absorbRouterCfg(r.router || {});
        this.settings.router.passwordInput = '';
        this.settings.router.sshPasswordInput = '';
        this.settings.router.unifi.passwordInput = '';
        this.settings.router.unifi.apiKeyInput = '';
      } catch (e) {
        this.error = e.message;
      } finally {
        this.settings.routerSaving = false;
      }
    },

    async testSsh() {
      this.settings.sshTesting = true;
      this.settings.sshTestResult = null;
      try {
        // Always persist the current toggles before testing -- saveRouter
        // is idempotent, and this avoids the "I ticked the box but the
        // server doesn't know about it yet" footgun.
        await this.saveRouter();
        const r = await this.api('/api/settings/router/ssh/test', {method: 'POST'});
        this.settings.sshTestResult = {
          ok: !!r.ok,
          message: `${r.host}:${r.port} · ${r.router?.model || ''}`.trim(),
          router: r.router,
          iptablesMatchSet: !!r.iptablesMatchSet,
        };
      } catch (e) {
        this.settings.sshTestResult = {ok: false, message: e.message};
      } finally {
        this.settings.sshTesting = false;
      }
    },

    async applyNow() {
      this.settings.applying = true;
      this.settings.applyResult = null;
      try {
        // Always save first so Apply Now reflects the toggles the user
        // is actually looking at, not whatever was last persisted.
        await this.saveRouter();
        const r = await this.api('/api/settings/router/apply-now', {method: 'POST'});
        this.settings.applyResult = r.status || {};
      } catch (e) {
        this.error = e.message;
      } finally {
        this.settings.applying = false;
      }
    },

    async testRouter() {
      this.settings.routerTesting = true;
      this.settings.routerTestResult = null;
      try {
        // If the user typed a new password (or API key, for UniFi) but
        // hasn't saved yet, save first so the test runs against the
        // credentials they actually intend.
        const needsSave =
          this.settings.router.passwordInput
          || this.settings.router.unifi.passwordInput
          || this.settings.router.unifi.apiKeyInput;
        if (needsSave) {
          await this.saveRouter();
        }
        const r = await this.api('/api/settings/router/test', {method: 'POST'});
        const info = r.info || {};
        const parts = [];
        if (r.vendor === 'unifi') {
          // UniFi summary line.
          if (info.flavour) parts.push(info.flavour);
          if (info.site) parts.push(`site ${info.site}`);
          if (typeof info.clientsCount === 'number') {
            parts.push(`${info.clientsCount} client(s)`);
          }
          if (typeof info.trafficRulesCount === 'number') {
            parts.push(`${info.trafficRulesCount} traffic rule(s)`);
          }
        } else {
          // ASUS summary line + auto-detected scheme/port mirror-back.
          if (info.model) parts.push(info.model);
          if (info.firmware) parts.push('fw ' + info.firmware);
          if (info.lanIp) parts.push('LAN ' + info.lanIp);
          if (r.detected) {
            const oldScheme = this.settings.router.scheme || 'http';
            const oldPort = this.settings.router.port || null;
            if (r.detected.scheme !== oldScheme ||
                String(r.detected.port) !== String(oldPort)) {
              this.settings.router.scheme = r.detected.scheme;
              this.settings.router.port = r.detected.port;
              parts.push(`auto-detected ${r.detected.scheme}://${r.detected.port}`);
            }
          }
        }
        this.settings.routerTestResult = {
          ok: true,
          message: parts.join(' · ') || 'Login OK',
          info: info,
        };
        if (this.settings.router.vendor === 'asus' && this.settings.router.enabled) {
          this.loadRouterClients();
        }
      } catch (e) {
        this.settings.routerTestResult = {ok: false, message: e.message};
      } finally {
        this.settings.routerTesting = false;
      }
    },

    async loadRouterClients() {
      this.settings.routerClientsLoading = true;
      this.settings.routerClientsError = null;
      try {
        const r = await this.api('/api/settings/router/clients');
        const list = (r.clients || []).slice().sort((a, b) => {
          if (a.online !== b.online) return a.online ? -1 : 1;
          return (a.name || a.ip || a.mac).localeCompare(b.name || b.ip || b.mac);
        });
        this.settings.routerClients = list;
      } catch (e) {
        this.settings.routerClientsError = e.message;
        this.settings.routerClients = null;
      } finally {
        this.settings.routerClientsLoading = false;
      }
    },

    // ---------------------------------------------------------- query inspector

    async openQueries(d) {
      this.inspector.open = true;
      this.inspector.device = d;
      this.inspector.entries = [];
      this.inspector.totalEntries = 0;
      this.inspector.blockedInPage = 0;
      await this.loadQueries();
    },
    closeQueries() { this.inspector.open = false; this.inspector.device = null; this.inspector.entries = []; },
    async loadQueries() {
      if (!this.inspector.device) return;
      this.inspector.loading = true;
      try {
        const r = await this.api(`/api/devices/${encodeURIComponent(this.inspector.device.ip)}/queries`);
        this.inspector.entries = r.entries || [];
        this.inspector.totalEntries = r.totalEntries || 0;
        this.inspector.blockedInPage = r.blockedInPage || 0;
      } catch (e) { this.error = e.message; }
      finally { this.inspector.loading = false; }
    },

    // ----------------------------------------------------------------- chart

    renderMainChart() {
      const canvas = document.getElementById('mainChart');
      if (!canvas || !this.mainChartData || !this.mainChartData.labels) return;
      const ctx = canvas.getContext('2d');
      const labels = this.mainChartData.labels;
      const datasets = (this.mainChartData.datasets || []).map(ds => ({
        label: ds.label,
        data: ds.data,
        borderColor: ds.borderColor,
        backgroundColor: ds.backgroundColor,
        fill: ds.fill,
        borderWidth: ds.borderWidth || 2,
        tension: 0.3,
        pointRadius: 0,
        pointHoverRadius: 4,
      }));
      if (this.mainChart) {
        this.mainChart.data.labels = labels;
        this.mainChart.data.datasets = datasets;
        this.mainChart.update('none');
        return;
      }
      this.mainChart = new Chart(ctx, {
        type: 'line',
        data: {labels, datasets},
        options: {
          responsive: true,
          maintainAspectRatio: false,
          interaction: {mode: 'index', intersect: false},
          plugins: {
            legend: {labels: {color: 'rgba(226,232,240,0.85)', boxWidth: 12, font: {size: 11}}},
            tooltip: {
              backgroundColor: 'rgba(15,23,42,0.95)',
              borderColor: 'rgba(99,102,241,0.4)',
              borderWidth: 1,
              titleColor: '#e2e8f0',
              bodyColor: '#cbd5e1',
            },
          },
          scales: {
            x: {grid: {color: 'rgba(148,163,184,0.07)'}, ticks: {color: 'rgba(148,163,184,0.7)', maxRotation: 0, autoSkip: true, maxTicksLimit: 8}},
            y: {grid: {color: 'rgba(148,163,184,0.07)'}, ticks: {color: 'rgba(148,163,184,0.7)'}, beginAtZero: true},
          },
        },
      });
    },

    // ----------------------------------------------------------------- API

    async api(path, opts = {}) {
      const headers = {'Content-Type': 'application/json', ...(opts.headers || {})};
      const r = await fetch(path, {credentials: 'same-origin', ...opts, headers});
      if (r.status === 401) { window.location.href = '/login'; throw new Error('Not signed in'); }
      const text = await r.text();
      let data; try { data = text ? JSON.parse(text) : {}; } catch { data = {raw: text}; }
      if (!r.ok) throw new Error(data.detail || data.error || `Request failed (${r.status})`);
      return data;
    },
  };
};
