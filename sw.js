const CACHE_NAME='ldm-shell-v136';
const SHELL=['./','./index.html','./manifest.webmanifest','./icons/icon-192.png','./icons/icon-512.png'];
self.addEventListener('install',event=>{event.waitUntil(caches.open(CACHE_NAME).then(cache=>cache.addAll(SHELL)));self.skipWaiting();});
self.addEventListener('activate',event=>{event.waitUntil((async()=>{for(const name of await caches.keys()){if(name.startsWith('ldm-shell-')&&name!==CACHE_NAME)await caches.delete(name);}await self.clients.claim();})());});
self.addEventListener('fetch',event=>{const req=event.request;if(req.method!=='GET'||new URL(req.url).origin!==self.location.origin)return;
if(req.mode==='navigate'){event.respondWith(fetch(req).then(response=>{if(response.ok){const copy=response.clone();caches.open(CACHE_NAME).then(cache=>cache.put('./index.html',copy));}return response;}).catch(()=>caches.match('./index.html')));return;}
if(new URL(req.url).pathname.endsWith('/sw.js'))return;
event.respondWith(caches.match(req).then(cached=>cached||fetch(req).then(response=>{if(response.ok&&req.url.startsWith(self.registration.scope)){const copy=response.clone();caches.open(CACHE_NAME).then(cache=>cache.put(req,copy));}return response;})));
});

self.addEventListener('push',event=>{let data={};try{data=event.data?event.data.json():{};}catch{}const title=String(data.title||'Liga CDM');event.waitUntil(self.registration.showNotification(title,{body:String(data.body||'Tienes una novedad en la liga.'),icon:'./icons/icon-192.png',badge:'./icons/icon-192.png',tag:String(data.tag||'ldm-alert'),data:{url:String(data.url||'./?view=pending')}}));});
self.addEventListener('notificationclick',event=>{event.notification.close();const target=new URL(event.notification.data?.url||'./',self.registration.scope).href;event.waitUntil((async()=>{const windows=await self.clients.matchAll({type:'window',includeUncontrolled:true});for(const c of windows){if(new URL(c.url).origin===new URL(target).origin){await c.focus();try{await c.navigate(target);}catch{}try{c.postMessage({type:'LDM_PUSH_NAVIGATE',url:target});}catch{}return;}}await self.clients.openWindow(target);})());});
