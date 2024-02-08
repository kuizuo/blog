## 前言
解决ssh因为代理无法连接github,

> 有时，防火墙会完全拒绝允许 SSH 连接。 如果无法选择使用[具有凭据缓存的 HTTPS 克隆](https://docs.github.com/zh/github/getting-started-with-github/caching-your-github-credentials-in-git)，可以尝试使用通过 HTTPS 端口建立的 SSH 连接克隆。 大多数防火墙规则应允许此操作，但代理服务器可能会干扰。

Sometimes, firewalls refuse to allow SSH connections entirely. If using [HTTPS cloning with credential caching](https://docs.github.com/en/github/getting-started-with-github/caching-your-github-credentials-in-git) is not an option, you can attempt to clone using an SSH connection made over the HTTPS port. Most firewall rules should allow this, but proxy servers may interfere.

ssh 通过 -p指定端口

**GitHub Enterprise Server users**: Accessing GitHub Enterprise Server via SSH over the HTTPS port is currently not supported.

To test if SSH over the HTTPS port is possible, run this SSH command:

```shell
$ ssh -T -p 443 git@ssh.github.com
> Hi USERNAME! You've successfully authenticated, but GitHub does not
> provide shell access.
```

**Note**: The hostname for port 443 is `ssh.github.com`, not `github.com`.

If that worked, great! If not, you may need to [follow our troubleshooting guide](https://docs.github.com/en/authentication/troubleshooting-ssh/error-permission-denied-publickey).

Now, to clone the repository, you can run the following command:

```shell
git clone ssh://git@ssh.github.com:443/YOUR-USERNAME/YOUR-REPOSITORY.git
```

## [Enabling SSH connections over HTTPS](https://docs.github.com/en/authentication/troubleshooting-ssh/using-ssh-over-the-https-port#enabling-ssh-connections-over-https)

If you are able to SSH into `git@ssh.github.com` over port 443, you can override your SSH settings to force any connection to GitHub.com to run through that server and port.

To set this in your SSH configuration file, edit the file at `~/.ssh/config`, and add this section:

```text
Host github.com
    Hostname ssh.github.com
    Port 443
    User git
```

You can test that this works by connecting once more to GitHub.com:

```shell
$ ssh -T git@github.com
> Hi USERNAME! You've successfully authenticated, but GitHub does not
> provide shell access.
```

## [Updating known hosts](https://docs.github.com/en/authentication/troubleshooting-ssh/using-ssh-over-the-https-port#updating-known-hosts)

The first time you interact with GitHub after switching to port 443, you may get a warning message that the host wasn't found in `known_hosts`, or that it was found by another name.

```shell
> The authenticity of host '[ssh.github.com]:443 ([140.82.112.36]:443)' can't be established.
> ED25519 key fingerprint is SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU.
> This host key is known by the following other names/addresses:
>     ~/.ssh/known_hosts:32: github.com
> Are you sure you want to continue connecting (yes/no/[fingerprint])?
```

It is safe to answer "yes" to this question, assuming that the SSH fingerprint matches one of GitHub's published fingerprints. For the list of fingerprints, see "[GitHub's SSH key fingerprints](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/githubs-ssh-key-fingerprints)."

## 参考链接

https://docs.github.com/en/authentication/troubleshooting-ssh/using-ssh-over-the-https-port#enabling-ssh-connections-over-https
