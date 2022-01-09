# package be.zardof.sshconfig
#
#   Copyright (c) 2012, Wim Thys <wim.thys@zardof.be>
#   All rights reserved.
#
#   Redistribution and use in source and binary forms, with or without
#   modification, are permitted provided that the following conditions are met:
#
#   * Redistributions of source code must retain the above copyright notice,
#     this list of conditions and the following disclaimer.
#   * Redistributions in binary form must reproduce the above copyright notice,
#     this list of conditions and the following disclaimer in the documentation
#     and/or other materials provided with the distribution.
#
#   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
#   AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
#   IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
#   ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
#   LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
#   CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
#   SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
#   INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
#   CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
#   ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
#   POSSIBILITY OF SUCH DAMAGE.
#
from os.path import expanduser

import copy


class SshConfig:
    """
    SSH configuration. An SshConfig consists of multiple SshConfigEntries, with
    at least one general entry applying to all hosts that could not be matched
    to other entries.
    """

    def __init__(self, default=None, **hosts):
        """ Create an SshConfig.

        @param default: The default values that must be used. Defaults to None.
        @keyword hosts: Host entries in the form of host=options where options
            is a SshConfigEntry. If options is None, the host will be ignored.
        """
        self.__entries = {}
        if not default is None:
            self.set(None, default)
        for h, e in hosts.items():
            if not e is None:
                self.set(h, e)

    def get(self, host, option=None):
        """ Get the entry for the host. If the host does not have an entry,
        None is returned. To get the default entry, use None as a value.
        If the option is supplied, this is equivalent to
        get(host).get(option)

        @param host: The hostname to look for.
        @param option: The option to look for.
        """
        host_name = "ssh_%s" % host
        if host is None:
            host_name = "default"

        if host_name not in self.__entries:
            return None

        if option is None:
            return self.__entries[host_name]
        else:
            return self.__entries[host_name].get(option)

    def set(self, host, entry=None, **options):
        """ Set the entry options for a specific host and create an entry if
        there is none yet. If this is a new host, it will have a priority equal
        to the number of entries. This can be changed with the set_priority()
        method of SshConfigEntry.

        @param host: The host to set the entry for.
        @param entry: The entry to set. Either a dict-like object with the
            options as keys or an SshConfigEntry.
        @keyword options: SSH options and a corresponding value in the form of
            option=value. If value is None, the option is ignored.
        """
        host_name = "ssh_%s" % host
        if host is None:
            host_name = "default"

        if (entry is None
            and len([1 for k in options
                     if (not options[k] is None
                     or len(options[k]) == 0)]) == 0):
            # Nothing to do, just exit
            return

        e = SshConfigEntry(len(self.__entries))

        if not entry is None:
            e.set(entry)

        if len(options) > 0:
            e.set(**options)

        # Guarantee that an entry will have entries
        if len(e) > 0:
            if host not in self or (host is None and "default" not in
                    self.__entries):
                self.__entries[host_name] = e
            else:
                self.get(host).set(e)

    def __delitem__(self, host):
        """ Remove an entire host entry
        @param host: the host entry to remove.
        """
        if host in self:
            del self.__entries["ssh_%s" % host]
        elif host is None:
            del self.__entries["default"]
        else:
            raise KeyError(host)

    def remove(self, host, *options):
        """ Remove a host entry or specific options in a host entry.

        @param host: the host for which to remove the entire entry
        @param options: the name of the options to be removed so that it does
            not exist afterwards. It need not exist beforehand. If no options
            are supplied, the host entry is removed.
        """
        if len(options) == 0:
            del self[host]
        else:
            entry = self.get(host)
            entry.remove(*options)
            if len(entry) == 0:
                self.remove(host)

    def __contains__(self, host):
        """ If we have an entry for the specified host

        @param host: The host to check for.
        """
        if host is None:
            return False
        host_name = "ssh_%s" % host
        return host_name in self.__entries

    def hosts(self):
        """ Return all the hostnames """
        return [x.partition("ssh_")[2] for x in self.__entries.keys() if
                x.find("ssh_", 0, 4) >= 0]

    def save(self, dest):
        """ Save the configuration somewhere safe.

        @param dest: A filename or a file-like object. If the file already
            exists, it will be overwritten.
        """
        if (isinstance(dest, file)):
            dest.write(str(self))
        elif isinstance(dest, str):
            f = open(dest, "w")
            f.write(str(self))
            f.close()
        else:
            raise TypeError("Argument is not a file or str")

    def load(self, config):
        """ Load a configuration.

        @param config: A configuration to load. Must be a file-like object or a
            filename.
        """
        cfg = load_sshconfig(config)
        hosts = [None]
        hosts.extend(cfg.hosts())
        for h in hosts:
            self.set(h, cfg.get(h))

    def __repr__(self):
        """ Representative string. Will encode a SshConfig as
        SshConfig(host=entry, ...). host will be the name for the host entry
        and entry will be encoded as SshConfigEntry.
        """
        rep = "SshConfig("
        entries = []
        for k, v in self.__entries.items():
            if v is None:
                continue
            if k == "default":
                entries.append(repr(v))
            else:
                entries.append("%s = %s" % (k.partition('ssh_')[2], repr(v)))
        rep += ", ".join(entries)
        rep += ")"
        return rep

    def __str__(self):
        """ Gives the ssh_config represenation of the entry. """
        lines = []
        sortfunc = lambda t: t[1].priority()
        for h, e in sorted(self.__entries.items(), key=sortfunc):
            opts = str(e)
            if not h == "default":
                lines.append("Host %s" % h.partition("ssh_")[2])
                opts = "\n".join(["    %s" % s for s in opts.split("\n")])
            lines.append(opts)
        return "\n".join(lines)


class SshConfigEntry:
    """ A collection of SSH options pertaining to a group of hosts """
    def __add_to_opts(self, ddict=None, llist=None, ttuple=None):
        try:
            k = self.__options
            del k
        except AttributeError:
            self.__options = {}

        if llist is not None and len(llist) > 0:
            for t in llist:
                if not (t[1] is None or t[0] is None):
                    self.__options[str(t[0])] = t[1]
        if ddict is not None and len(ddict) > 0:
            for o, v in ddict.items():
                if not (o is None or v is None):
                    self.__options[o] = v
        if ttuple is not None and len(ttuple) >= 2:
            if not (ttuple[0] is None or ttuple[1] is None):
                self.__options[ttuple[0]] = ttuple[1]

    def __init__(self, priority, entry=None, **options):
        """ Create an SshConfigEntry.

        @param priority: The priority for this entry.
        @param entry: The contents of the entry. Can be either another
            SshConfigEntry or a dict-like object.
        @keyword options: Options in the form of option=value where value is
            the value for the option. If value is None, option is ignored.
        """
        self.__options = {}
        self.__priority = priority

        if not entry is None:
            if isinstance(entry, SshConfigEntry):
                    opts = entry.items()
                    self.__add_to_opts(ddict=opts)
            elif isinstance(entry, dict):
                self.__add_to_opts(ddict=entry)
            else:
                err = "SshConfigEntry(entry): entry is not"
                err += " of type SshConfigEntry or dict"
                raise TypeError(err)

        if len(options) > 0:
            self.__add_to_opts(ddict=options)

    def priority(self):
        """ Get the priority of this host entry. This is used for ordering in
        the eventual ssh_config.
        """
        return self.__priority

    def set_priority(self, priority):
        """ Set the priority of the entry. If None is supplied, nothing
        happens.

        @param priority: The new priority. A value of None will have no effect
        """
        if priority is None:
            return
        else:
            self.__priority = int(priority)

    def get(self, option):
        """ Get the value for a specific option.

        @param option: A valid SSH option. If it does not exist, None is
            returned.
        """
        try:
            return self.__options[option]
        except KeyError:
            return None

    def set(self, option=None, value=None, **options):
        """ Set the value for a specific option. Options with a name or value
        of None will be ignored.

        @param option: An SshConfigEntry or a dict-like object with SSH
            options as keys.

        @param option: A valid SSH option name
        @param value: Value for the option

        @keyword options: Options in the form of option=value where
            value is the value for option. If value is None, option is
            ignored.
        """
        if not option is None and value is None:
            if isinstance(option, SshConfigEntry):
                self.__add_to_opts(ddict=option.__options)
                self.set_priority(option.priority())
            elif isinstance(option, dict):
                self.__add_to_opts(ddict=option)
            else:
                pass
        elif not option is None and not value is None:
            self.__add_to_opts(ttuple=(option, value))

        if len(options) > 0:
            self.__add_to_opts(ddict=options)

    def remove(self, option, *options):
        """ Remove the specified entries.

        @param option: The option to remove. It will not exist afterwards. It
            need not exist beforehand.
        @param options: The additional options to remove (optional).
        """
        opts = [option]
        opts.extend(options)
        for opt in opts:
            try:
                del self[opt]
            except KeyError:
                pass

    def __delitem__(self, option):
        """ Remove the specified option.
        @param option: the option to remove.
        @raise KeyError: when the option does not exist.
        """
        if option in self:
            del self.__options[option]
        else:
            raise KeyError(option)

    def __contains__(self, option):
        """ Whether the SshConfigEntry contains the specified option

        @param option: A valid SSH option
        """
        return option in self.__options

    def __len__(self):
        """ Return the number of defined options """
        return len(self.__options)

    def to_dict(self):
        """ Converts the SshConfigEntry to a dict. """
        l = {}
        l.update(self.__options)
        return l

    def items(self):
        """ Return the options that have a value. """
        return [x for x in self.__options.items() if not x[1] is None]

    def options(self):
        """ Return all option names. """
        l = []
        l.extend([str(x[0]) for x in self.items()])
        return l

    def __repr__(self):
        """ Representative string. Will encode as
        SshConfigEntry(priority, optionN=valueN, ...). """
        rep = "SshConfigEntry(%d" % self.priority()
        entries = []
        for k, v in self.__options.items():
            if v is None:
                continue
            entries.append("%s = \"%s\"" % (k, v))
        if len(entries) > 0:
            rep += ", "
        rep += ", ".join(entries)
        rep += ")"
        return rep

    def __str__(self):
        """ String representation resulting in ssh_config-like formatting. """
        lines = []
        for k, v in self.__options.items():
            if v is None:
                continue
            lines.append("%s %s" % (k, v))
        return "\n".join(lines)


def load_sshconfig(config):
    """ Parses a ssh_config to an SshConfig

    @param config: A filename or a file-like object.
    """
    cfgfile = []
    if isinstance(config, str):
        k = open(config, 'r')
        cfgfile = k.readlines()
        k.close()
    elif isinstance(config, file):
        cfgfile = config.readlines()
    else:
        raise TypeError("config is not a string or file")

    ssh_cfg = SshConfig()
    host_name = None
    host_entry = SshConfigEntry(0)
    priority = 0
    for line in cfgfile:
        line = line.strip().split('#')[0]
        option = line.split(' ')[0]
        value = " ".join(line.strip().split(' ')[1:])

        if len(option) == 0:
            # we have a comment!
            continue
        elif option == "Host":
            ssh_cfg.set(host_name, host_entry)
            priority += 1

            host_name = value
            host_entry = SshConfigEntry(priority)
        else:
            host_entry.set(option, value)
    ssh_cfg.set(host_name, host_entry)

    return ssh_cfg
