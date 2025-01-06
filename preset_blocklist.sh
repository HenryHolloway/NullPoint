#!/bin/bash
read -p "Block reddit and reddit alternate frontend interfaces? (y/n): " user_input
if [[ "${user_input,,}" == *"y"* ]]; then
    sudo nullpoint block old.reddit.com
    sudo nullpoint block reddit.com
    sudo nullpoint block safereddit.com
    sudo nullpoint block eu.safereddit.com
    sudo nullpoint block l.opnxng.com
    sudo nullpoint block libreddit.projectsegfau.lt
    sudo nullpoint block libreddit.bus-hit.me
    sudo nullpoint block reddit.invak.id
    sudo nullpoint block redlib.catsarch.com
    sudo nullpoint block reddit.idevicehacked.com
    sudo nullpoint block redlib.matthew.science
    sudo nullpoint block redlib.freedit.eu
    sudo nullpoint block redlib.perennialte.ch
    sudo nullpoint block redlib.tux.pizza
    sudo nullpoint block redlib.vimmer.dev
    sudo nullpoint block libreddit.privacydev.net
    sudo nullpoint block lr.n8pjl.ca
    sudo nullpoint block rl.bloat.cat
    sudo nullpoint block redlib.xn--hackerhhle-kcb.org/
    sudo nullpoint block redlib.nohost.network
    sudo nullpoint block redlib.r4fo.com
    sudo nullpoint block reddit.owo.si
    sudo nullpoint block redlib.ducks.party
    sudo nullpoint block red.ngn.tf
    sudo nullpoint block red.artemislena.eu
    sudo nullpoint block redlib.dnfetheus.xyz
    sudo nullpoint block redlib.cow.rip
    sudo nullpoint block libreddit.eu.org
    sudo nullpoint block r.darrennathanael.com
    sudo nullpoint block redlib.kittywi.re
    sudo nullpoint block redlib.privacyredirect.com
    sudo nullpoint block redlib.seasi.dev
    sudo nullpoint block redlib.mask.sh
    sudo nullpoint block redlib.incogniweb.net
    sudo nullpoint block reddit.nerdvpn.de
    sudo nullpoint block lr.ggtyler.dev
    sudo nullpoint block redlib.baczek.me
    sudo nullpoint block redlib.privacy.deals
    sudo nullpoint block lr.quitaxd.online
    sudo nullpoint block redlib.nadeko.net
    sudo nullpoint block redlib.nirn.quest
    sudo nullpoint block redlib.nezumi.party
    sudo nullpoint block redlib.private.coffee
    sudo nullpoint block redlib.4o1x5.dev
    sudo nullpoint block redlib.frontendfriendly.xyz
    sudo nullpoint block rl.rootdo.com
    sudo nullpoint block red.arancia.click
    sudo nullpoint block redlib.reallyaweso.me
    sudo nullpoint block redlib.privacy.com.de

    echo "Wow! I didn't even know there were so many places to look at reddit!"
fi

