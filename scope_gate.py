"""Offline authorization checks for IP/hostname/port/protocol target inventories."""
import argparse
from datetime import datetime, timezone
import ipaddress
import json
import sys


def utc(value):
    parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
    if parsed.tzinfo is None:
        raise ValueError('Authorization timestamps require an explicit timezone')
    return parsed.astimezone(timezone.utc)


def hostname(value):
    result = value.rstrip('.').encode('idna').decode('ascii').lower()
    if not result or len(result) > 253 or any(not label or len(label) > 63 or label.startswith('-') or label.endswith('-') or any(c not in 'abcdefghijklmnopqrstuvwxyz0123456789-' for c in label) for label in result.split('.')):
        raise ValueError(f'Invalid hostname: {value}')
    return result


def matches(target, rule):
    try:
        address = ipaddress.ip_address(target)
    except ValueError:
        address = None
    if address is not None:
        try:
            return address in ipaddress.ip_network(rule, strict=True)
        except ValueError:
            return False
    if '/' in rule or ':' in rule:
        return False
    name = hostname(target)
    if rule.startswith('*.'):
        suffix = hostname(rule[2:])
        return name.endswith('.' + suffix)
    return name == hostname(rule)


def validate(policy):
    for field in ('engagement_id', 'approved_by', 'valid_from', 'valid_until', 'allow', 'deny', 'services'):
        if field not in policy:
            raise ValueError(f'Missing policy field: {field}')
    if not policy['engagement_id'] or not policy['approved_by']:
        raise ValueError('Engagement and approver must be nonempty')
    if utc(policy['valid_from']) >= utc(policy['valid_until']):
        raise ValueError('Invalid authorization window')
    for field in ('allow', 'deny'):
        if not isinstance(policy[field], list):
            raise ValueError(f'{field} must be a list')
        for rule in policy[field]:
            if '/' in rule or ':' in rule:
                ipaddress.ip_network(rule, strict=True)
            else:
                try:
                    ipaddress.ip_address(rule)
                except ValueError:
                    hostname(rule[2:] if rule.startswith('*.') else rule)
    if not isinstance(policy['services'], list) or not policy['services']:
        raise ValueError('Explicit services are required')
    for service in policy['services']:
        if service['protocol'] not in ('tcp', 'udp') or type(service['port']) is not int or not 1 <= service['port'] <= 65535:
            raise ValueError('Invalid service definition')


def decide(policy, target, now=None):
    validate(policy)
    now = now or datetime.now(timezone.utc)
    if now.tzinfo is None:
        raise ValueError('Evaluation time requires timezone')
    name = target['host']
    # Validate even if the approval window is closed.
    try:
        ipaddress.ip_address(name)
    except ValueError:
        hostname(name)
    service = {'protocol': target['protocol'], 'port': target['port']}
    if service['protocol'] not in ('tcp', 'udp') or type(service['port']) is not int or not 1 <= service['port'] <= 65535:
        raise ValueError('Invalid target service')
    if not utc(policy['valid_from']) <= now < utc(policy['valid_until']):
        reason = 'outside_authorization_window'
    elif any(matches(name, rule) for rule in policy['deny']):
        reason = 'explicit_deny'
    elif not any(matches(name, rule) for rule in policy['allow']):
        reason = 'no_allow_rule'
    elif service not in policy['services']:
        reason = 'service_not_authorized'
    else:
        reason = 'authorized'
    return {**target, 'allowed': reason == 'authorized', 'reason': reason, 'engagement_id': policy['engagement_id']}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('policy')
    parser.add_argument('targets')
    parser.add_argument('--at', help='Explicit timestamp for reproducible historical evaluation')
    args = parser.parse_args(argv)
    try:
        with open(args.policy, encoding='utf-8') as stream:
            policy = json.load(stream)
        with open(args.targets, encoding='utf-8') as stream:
            targets = json.load(stream)
        validate(policy)
        if not isinstance(targets, list) or not targets:
            raise ValueError('Targets must be a nonempty list')
        now = utc(args.at) if args.at else datetime.now(timezone.utc)
        results = [decide(policy, target, now) for target in targets]
        print(json.dumps(results, indent=2))
        return int(any(not result['allowed'] for result in results))
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as error:
        print(f'error: {error}', file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
