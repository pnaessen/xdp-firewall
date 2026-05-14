# XDP-Firewall : High-Performance eBPF Packet Filter

##  Description
Implémentation d'un pare-feu réseau de bas niveau utilisant la technologie **eBPF/XDP (eXpress Data Path)** pour le filtrage de paquets à haute performance (Kernel Bypass).
Ce projet démontre la capacité à contourner la pile réseau classique de l'OS pour traiter les paquets directement au niveau du pilote de la carte réseau, offrant une protection anti-DDoS avec une latence quasi nulle.

##  Architecture

* **Kernel Space (C)** : Un programme eBPF attaché au point d'ancrage XDP. Il intercepte les trames Ethernet/IPv4 brutes directement depuis le DMA, effectue des vérifications de limites strictes (Boundary Checks), et rejette (`XDP_DROP`) les paquets ICMP.
* **User Space (Go)** : Un démon de supervision orchestrant le cycle de vie du programme eBPF (chargement, attachement, détachement sécurisé via signaux POSIX).
* **Communication Lockless (PERCPU_HASH)** : La communication entre le noyau et l'espace utilisateur s'effectue via une map eBPF de type `BPF_MAP_TYPE_PERCPU_HASH`. Cette architecture sans mutex garantit la remontée haute-performance des statistiques par CPU.

**Résultat attendu :** Les paquets ICMP seront détruits instantanément au niveau du pilote de la carte réseau de la machine hôte. Le terminal du pare-feu affichera l'interception en temps réel.

---



```bash
go generate ./bpf
```
Cette commande :
- Exécute le build tag `//go:generate` dans `bpf/gen.go`
- Appelle `bpf2go` pour compiler `xdp_filter.c` en bytecode eBPF
- Génère les fichiers `bpf_bpfel.go` et `bpf_bpfeb.go` (little/big endian)

```bash
go build -o xdp-firewall
```



### main.go
- `LoadBpfObjects()`: Charge le bytecode eBPF compilé en mémoire kernel
- `AttachXDP()`: Attache le programme au hook XDP de l'interface réseau
- Goroutine d'affichage: Lit la map `icmp_stats` chaque seconde
- Graceful shutdown: Nettoie les ressources via signaux POSIX

### xdp_filter.c
- **Boundary checks** : Validation stricte des limites du paquet (eBPF verifier requirement)
- **PERCPU_HASH** : Pas de contention entre CPUs, lecture atomique du compteur


