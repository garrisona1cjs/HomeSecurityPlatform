// =======================================
// LayerSeven Threat Intelligence Engine
// =======================================


// ================================
// CONFIG
// ================================
const severityColors = {
    critical: "#ff0033",
    high: "#ff6600",
    medium: "#00ffff",
    low: "#00ccff"
};


let originIntensity = {};
let activeOrigins = {};
let attackCount = 0;
let defensePressure = 0;
let heatZones = {};
let recentTargets = [];
let lastDrawTime = 0;
let escalationLevel = 1;


// ================================
// 🔊 SOUND ALERTS
// ================================
const criticalSound = new Audio("https://actions.google.com/sounds/v1/alarms/beep_short.ogg");
criticalSound.volume = 0.3;

let soundEnabled = false;

document.addEventListener("click", () => soundEnabled = true, { once: true });
document.addEventListener("keydown", () => soundEnabled = true, { once: true });

// ================================
// 🔊 DYNAMIC THREAT SOUND LAYERS
// ================================
const alertLow = new Audio("https://actions.google.com/sounds/v1/alarms/beep_short.ogg");
const alertHigh = new Audio("https://actions.google.com/sounds/v1/alarms/digital_watch_alarm_long.ogg");

alertLow.volume = 0.15;
alertHigh.volume = 0.25;

function playThreatAudio(level) {
    if (!soundEnabled) return;

    if (level === 2) {
        alertLow.currentTime = 0;
        alertLow.play().catch(()=>{});
    }

    if (level === 3) {
        alertHigh.currentTime = 0;
        alertHigh.play().catch(()=>{});
    }
}


// ================================
// 📊 LIVE ATTACK COUNTER
// ================================
function updateAttackCounter() {

    let counter = document.getElementById("attackCounter");

    if (!counter) {
        counter = document.createElement("div");
        counter.id = "attackCounter";
        counter.style.cssText = `
            position:absolute;
            top:10px;
            right:15px;
            color:#00ffff;
            font-family:monospace;
            font-size:18px;
            z-index:999;
        `;
        document.body.appendChild(counter);
    }

    counter.innerHTML = "⚡ ATTACKS: " + attackCount;
}

// ================================
// 🎬 ESCALATION LEVEL ENGINE
// ================================
function updateEscalationLevel() {

    if (defensePressure > 12) escalationLevel = 3;
    else if (defensePressure > 6) escalationLevel = 2;
    else escalationLevel = 1;

    playThreatAudio(escalationLevel);
}


// ================================
// 🟢 ORIGIN HEAT GLOW
// ================================
function createOriginPulse(map, location) {

    const key = location.toString();
    originIntensity[key] = (originIntensity[key] || 0) + 1;

    const intensity = Math.min(originIntensity[key], 8);

    const glowColor = `rgba(255, 60, 60, ${0.1 + intensity * 0.08})`;

    const aura = L.circle(location, {
        radius: 25000 + intensity * 6000,
        color: glowColor,
        weight: 0,
        fillColor: glowColor,
        fillOpacity: 0.25
    }).addTo(map);

    setTimeout(() => map.removeLayer(aura), 1200);
}


// ================================
// 🌍 COUNTRY AURA
// ================================
function createCountryAura(map, location) {

    const aura = L.circle(location, {
        radius: 90000,
        color: "rgba(255,0,0,0.15)",
        weight: 0,
        fillColor: "rgba(255,0,0,0.15)",
        fillOpacity: 0.15
    }).addTo(map);

    setTimeout(() => map.removeLayer(aura), 2000);
}


// ================================
// 🌍 HEAT ZONE
// ================================
function updateHeatZone(map, location) {

    const key = location.toString();
    heatZones[key] = (heatZones[key] || 0) + 1;

    const intensity = Math.min(heatZones[key], 6);

    const heat = L.circle(location, {
        radius: 40000 + intensity * 12000,
        color: "rgba(255,80,80,0.2)",
        weight: 0,
        fillColor: "rgba(255,80,80,0.2)",
        fillOpacity: 0.15
    }).addTo(map);

    setTimeout(() => map.removeLayer(heat), 2000);
}


// ================================
// 💥 IMPACT FLASH
// ================================
function createImpactFlash(map, location, color) {

    const ring = L.circle(location, {
        radius: 20000,
        color,
        weight: 2,
        opacity: 0.7,
        fillOpacity: 0
    }).addTo(map);

    let radius = 20000;
    let opacity = 0.7;

    function animate() {
        radius += 16000;
        opacity -= 0.05;

        ring.setRadius(radius);
        ring.setStyle({ opacity });

        if (opacity > 0) requestAnimationFrame(animate);
        else map.removeLayer(ring);
    }

    animate();
}


// ================================
// 🛡 SHIELD IMPACT
// ================================
function createShieldImpact(map, location) {

    const shield = L.circle(location, {
        radius: 15000,
        color: "#00ccff",
        weight: 3,
        opacity: 0.9,
        fillColor: "#00ccff",
        fillOpacity: 0.15
    }).addTo(map);

    let radius = 15000;
    let opacity = 0.9;

    function animate() {
        radius += 18000;
        opacity -= 0.05;

        shield.setRadius(radius);
        shield.setStyle({ opacity });

        if (opacity > 0) requestAnimationFrame(animate);
        else map.removeLayer(shield);
    }

    animate();
}


// ================================
// 🛡 SHIELD RIPPLE
// ================================
function createShieldRipple(map, location, severity) {

    const ripple = L.circle(location, {
        radius: 20000,
        color: "#00e6ff",
        weight: severity === "critical" ? 3 : 2,
        opacity: 0.6,
        fillOpacity: 0
    }).addTo(map);

    let radius = 20000;
    let opacity = 0.6;

    function animate() {
        radius += severity === "critical" ? 26000 : 18000;
        opacity -= 0.05;

        ripple.setRadius(radius);
        ripple.setStyle({ opacity });

        if (opacity > 0) requestAnimationFrame(animate);
        else map.removeLayer(ripple);
    }

    animate();
}


// ================================
// ⚡ INTERCEPT BEAM
// ================================
function createInterceptBeam(map, from, to, severity) {



    const beam = L.polyline([from, to], {
        color: "#00ffff",
        weight: severity === "critical" ? 3 : 2,
        opacity: 0.9,
        dashArray: "6,8"
    }).addTo(map);

    let opacity = 0.9;

    function fade() {
        opacity -= 0.05;
        beam.setStyle({ opacity });
        if (opacity > 0) requestAnimationFrame(fade);
        else map.removeLayer(beam);
    }

    fade();
}


// ================================
// ⚡ TRAJECTORY PROJECTION
// ================================
function drawThreatTrajectory(map, from, to) {
    const lat = to[0] + (to[0] - from[0]) * 0.25;
    const lng = to[1] + (to[1] - from[1]) * 0.25;

    const line = L.polyline([to, [lat, lng]], {
        color: "#00ffff",
        weight: 1,
        opacity: 0.35,
        dashArray: "2,10"
    }).addTo(map);

    setTimeout(() => map.removeLayer(line), 900);
}


// ================================
// 🛰 SATELLITE LOCK
// ================================
function satelliteLock(map, location) {
    const offsets = [[0.4,0.4],[-0.4,0.4],[0.4,-0.4]];
    offsets.forEach(offset => {
        const marker = L.circle(
            [location[0]+offset[0], location[1]+offset[1]],
            { radius:6000, color:"#66ffff", weight:1, opacity:0.6, fillOpacity:0 }
        ).addTo(map);
        setTimeout(()=>map.removeLayer(marker),800);
    });
}


// ================================
// 🛰 ORBITAL DEFENSE PULSE
// ================================
function orbitalPulse(map, location) {
    const pulse = L.circle(location,{
        radius:30000,
        color:"#00ffff",
        weight:2,
        opacity:0.6,
        fillOpacity:0
    }).addTo(map);

    let radius=30000, opacity=0.6;

    function animate(){
        radius+=20000;
        opacity-=0.05;
        pulse.setRadius(radius);
        pulse.setStyle({opacity});
        if(opacity>0) requestAnimationFrame(animate);
        else map.removeLayer(pulse);
    }
    animate();
}


// ================================
// 🌍 GLOBAL DEFENSE PULSE
// ================================
function globalDefensePulse(map){
    const grid=L.circle([20,0],{
        radius:9000000,
        color:"#00ffff",
        weight:1,
        opacity:0.08,
        fillOpacity:0
    }).addTo(map);

    setTimeout(()=>map.removeLayer(grid),1200);
}


// ================================
// 🔥 DRAW ATTACK BEAM
// ================================
function drawAttackBeam(map, fromCoords, toCoords, severity="medium") {

    // ================================
    // ⚡ PERFORMANCE THROTTLE
    // ================================
    const now = Date.now();
    if (now - lastDrawTime < 60) return;
    lastDrawTime = now;


    if (!window.shieldDomeInitialized) {
        shieldDomeLayer = L.circle(toCoords,{
            radius:180000,
            color:"#00ccff",
            weight:2,
            opacity:0.45,
            fillColor:"#00ccff",
            fillOpacity:0.08
        }).addTo(map);

        window.shieldDomeInitialized = true;
    }



    attackCount++;
    defensePressure++;
    updateAttackCounter();
    updateEscalationLevel();

    // ================================
    // ⭐ CINEMATIC ESCALATION LEVEL
    // ================================
    if (defensePressure > 12) escalationLevel = 3;
    else if (defensePressure > 6) escalationLevel = 2;
    else escalationLevel = 1;

    playThreatAudio(escalationLevel);


    createOriginPulse(map, fromCoords);
    createCountryAura(map, fromCoords);
    updateHeatZone(map, fromCoords);
    detectThreatCluster(map, fromCoords);

    // ================================
    // 🌍 THREAT CLUSTER DETECTION
    // ================================
    function detectThreatCluster(map, location) {

        const key = location.toString();

        if (heatZones[key] >= 4) {

            const cluster = L.circle(location, {
                radius: 120000,
                color: "#ff3300",
                weight: 1,
                opacity: 0.4,
                fillColor: "#ff3300",
                fillOpacity: 0.15
            }).addTo(map);

            setTimeout(() => map.removeLayer(cluster), 2500);
        }
    }

    const color = severityColors[severity] || "#00ffff";

    // track recent targets
    recentTargets.push(toCoords);
    if (recentTargets.length > 5) recentTargets.shift();

    const beam = L.polyline([fromCoords,toCoords],{
        color,
        weight: severity==="critical"?4:2,
        opacity: severity==="critical"?0.18:0.10
    }).addTo(map);

    if (severity === "critical") {

        if(soundEnabled){
            const now=Date.now();
            if(!window.lastSoundTime||now-window.lastSoundTime>800){
                criticalSound.currentTime=0;
                criticalSound.play().catch(()=>{});
                window.lastSoundTime=now;
            }
        }

        // ================================
        // ⭐ ESCALATION VISUAL RESPONSE
        // ================================
        if (escalationLevel >= 2) {
            orbitalPulse(map, toCoords);
        }

        if (escalationLevel === 3) {
            globalDefensePulse(map);
        }

        createImpactFlash(map, fromCoords, "#ff0033");

        if (!window.lastGlobalPulse || Date.now()-window.lastGlobalPulse>1500){
            globalDefensePulse(map);
            window.lastGlobalPulse=Date.now();
        }

        createShieldImpact(map,toCoords);
        orbitalPulse(map,toCoords);
        satelliteLock(map,toCoords);

        defenseResponseDelay(() => {
        multiIntercept(map, recentTargets, severity);
        }, severity);
    }

    // ================================
    // 🤖 AI RESPONSE DELAY
    // ================================
    function defenseResponseDelay(callback, severity) {

        const delay =
            severity === "critical" ? 80 :
            severity === "high" ? 160 :
            severity === "medium" ? 260 :
            340;

        setTimeout(callback, delay);
    }

    // ================================
    // 🛰 MULTI TARGET INTERCEPTION
    // ================================
    function multiIntercept(map, targets, severity) {

        if (!shieldDomeLayer) return;

        const domeCenter = shieldDomeLayer.getLatLng();

        targets.forEach((target, i) => {
            setTimeout(() => {
                createInterceptBeam(map, domeCenter, target, severity);
            }, i * 120); // stagger fire
        });
    }

    animatePacket(map, fromCoords, toCoords, color);
    drawThreatTrajectory(map, fromCoords, toCoords);
    createShieldRipple(map, toCoords, severity);
}
























