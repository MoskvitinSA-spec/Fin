function finTarget(u){
  var scope=self.registration.scope; // https://host/Fin/
  try{
    if(!u)return scope+'index.html';
    var abs=new URL(u, scope);
    if(abs.origin!==self.location.origin)return scope+'index.html';
    if(abs.href.indexOf(scope)!==0){ // legacy "/dashboard.html" style path
      abs=new URL(abs.pathname.replace(/^\/+/,'')+abs.search+abs.hash, scope);
    }
    return abs.href;
  }catch(e){return scope+'index.html';}
}
self.addEventListener('install',function(){self.skipWaiting();});
self.addEventListener('activate',function(e){e.waitUntil(self.clients.claim());});
self.addEventListener('push',function(event){
  var title='Finance',body='',url='';
  if(event.data){try{var d=event.data.json();if(d&&typeof d==='object'){if(d.title)title=String(d.title);if(d.body)body=String(d.body);if(d.url)url=String(d.url);}}catch(e){body=event.data.text();}}
  event.waitUntil(self.registration.showNotification(title,{body:body,data:{url:finTarget(url)}}));
});
self.addEventListener('notificationclick',function(event){
  event.notification.close();
  var target=finTarget(event.notification&&event.notification.data&&event.notification.data.url);
  event.waitUntil(clients.matchAll({type:'window',includeUncontrolled:true}).then(function(wins){
    for(var i=0;i<wins.length;i++){var c=wins[i];if(c.url&&c.url.split('?')[0]===target&&'focus'in c)return c.focus();}
    for(var j=0;j<wins.length;j++){var w=wins[j];if(w&&'navigate'in w){return Promise.resolve(w.navigate(target)).then(function(x){return (x||w).focus();}).catch(function(){return clients.openWindow?clients.openWindow(target):null;});}}
    if(clients.openWindow)return clients.openWindow(target);
  }));
});
