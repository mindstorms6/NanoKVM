import { useEffect, useState } from 'react';
import { useAuth } from '@/contexts/auth.ts';
import { Alert, App, Button, Form, Input, Select, Space, Spin, Switch } from 'antd';
import { useTranslation } from 'react-i18next';

import {
  AuthenticationSettings,
  getAuthenticationSettings,
  getUsers,
  saveAuthenticationSettings,
  User
} from '@/api/auth.ts';
import { notifyAuthRefresh } from '@/lib/auth-events.ts';

export const Authentication = () => {
  const { t } = useTranslation();
  const { message } = App.useApp();
  const { account } = useAuth();
  const [form] = Form.useForm<AuthenticationSettings & { clearClientSecret?: boolean }>();
  const [loaded, setLoaded] = useState(false);
  const [error, setError] = useState('');
  const [saving, setSaving] = useState(false);
  const [secretConfigured, setSecretConfigured] = useState(false);
  const [users, setUsers] = useState<User[]>([]);
  const oidcEnabled = Form.useWatch(['oidc', 'enabled'], form);
  const localEnabled = Form.useWatch('localEnabled', form);

  useEffect(() => {
    let active = true;
    Promise.all([getAuthenticationSettings(), getUsers()])
      .then(([settings, accounts]) => {
        if (!active) return;
        if (settings.code !== 0 || accounts.code !== 0) throw new Error(t('authMethods.loadError'));
        form.setFieldsValue(settings.data.settings);
        setSecretConfigured(settings.data.clientSecretConfigured);
        setUsers(accounts.data.users);
        setLoaded(true);
      })
      .catch(() => {
        if (active) setError(t('authMethods.loadError'));
      });
    return () => {
      active = false;
    };
  }, [form, t]);

  async function save(values: AuthenticationSettings & { clearClientSecret?: boolean }) {
    setSaving(true);
    setError('');
    try {
      const { clearClientSecret, ...settings } = values;
      const rsp = await saveAuthenticationSettings(settings, clearClientSecret);
      if (rsp.code !== 0) {
        setError(rsp.msg || t('authMethods.saveError'));
        return;
      }
      form.setFieldsValue({
        ...rsp.data.settings,
        oidc: { ...rsp.data.settings.oidc, clientSecret: '' },
        clearClientSecret: false
      });
      setSecretConfigured(rsp.data.clientSecretConfigured);
      message.success(t('authMethods.saved'));
      notifyAuthRefresh();
    } catch {
      setError(t('authMethods.saveError'));
    } finally {
      setSaving(false);
    }
  }

  return (
    <div>
      <div className="mb-4 text-base">{t('authMethods.title')}</div>
      {error && <Alert className="mb-4" type="error" showIcon message={error} />}
      {!loaded && !error && <Spin />}
      <Form form={form} layout="vertical" onFinish={save} disabled={!loaded || saving}>
        <Form.Item name="revision" hidden>
          <Input />
        </Form.Item>
        <Form.Item
          name="localEnabled"
          label={t('authMethods.local')}
          valuePropName="checked"
          extra={t('authMethods.localHelp')}
        >
          <Switch disabled={!oidcEnabled || account.authMethod !== 'oidc'} />
        </Form.Item>
        <Form.Item
          name="mcpKeyEnabled"
          label={t('authMethods.mcp')}
          valuePropName="checked"
          extra={t('authMethods.mcpHelp')}
        >
          <Switch />
        </Form.Item>
        <Form.Item name={['oidc', 'enabled']} label={t('authMethods.oidc')} valuePropName="checked">
          <Switch disabled={!localEnabled} />
        </Form.Item>
        <div hidden={!oidcEnabled}>
          <Alert
            className="mb-4"
            type="info"
            showIcon
            message={t('authMethods.setup')}
            description={t('authMethods.setupHelp')}
          />
          <Form.Item name={['oidc', 'displayName']} label={t('authMethods.displayName')}>
            <Input maxLength={80} placeholder="Keycloak" />
          </Form.Item>
          <Form.Item
            name={['oidc', 'issuer']}
            label={t('authMethods.issuer')}
            rules={[{ required: !!oidcEnabled }]}
          >
            <Input placeholder="https://sso.example.com/realms/home" />
          </Form.Item>
          <Form.Item
            name={['oidc', 'clientId']}
            label={t('authMethods.clientId')}
            rules={[{ required: !!oidcEnabled }]}
          >
            <Input autoComplete="off" />
          </Form.Item>
          <Form.Item
            name={['oidc', 'clientSecret']}
            label={t('authMethods.clientSecret')}
            extra={t('authMethods.secretHelp')}
          >
            <Input.Password
              autoComplete="new-password"
              placeholder={
                secretConfigured ? t('authMethods.secretSaved') : t('authMethods.secretOptional')
              }
            />
          </Form.Item>
          {secretConfigured && (
            <Form.Item
              name="clearClientSecret"
              label={t('authMethods.clearSecret')}
              valuePropName="checked"
            >
              <Switch />
            </Form.Item>
          )}
          <Form.Item
            name={['oidc', 'redirectUrl']}
            label={t('authMethods.redirectUrl')}
            extra={t('authMethods.redirectHelp')}
            rules={[{ required: !!oidcEnabled }]}
          >
            <Input placeholder={`${window.location.origin}/api/auth/oidc/callback`} />
          </Form.Item>
          <Form.Item
            name={['oidc', 'scopes']}
            label={t('authMethods.scopes')}
            extra={t('authMethods.scopesHelp')}
          >
            <Select mode="tags" tokenSeparators={[' ', ',']} />
          </Form.Item>
          <div className="mb-2">{t('authMethods.bindings')}</div>
          <p className="mb-4 text-sm text-neutral-400">{t('authMethods.bindingsHelp')}</p>
          <Form.List name={['oidc', 'bindings']}>
            {(fields, { add, remove }) => (
              <>
                {fields.map((field) => (
                  <div key={field.key} className="mb-4 rounded border border-neutral-700 p-3">
                    <Form.Item
                      name={[field.name, 'subject']}
                      label={t('authMethods.subject')}
                      rules={[{ required: !!oidcEnabled }]}
                    >
                      <Input maxLength={255} />
                    </Form.Item>
                    <Form.Item
                      name={[field.name, 'username']}
                      label={t('authMethods.account')}
                      rules={[{ required: !!oidcEnabled }]}
                    >
                      <Select
                        options={users.map((user) => ({
                          value: user.username,
                          label: `${user.username} (${user.role})`,
                          disabled: !user.enabled
                        }))}
                      />
                    </Form.Item>
                    <Button danger onClick={() => remove(field.name)}>
                      {t('authMethods.remove')}
                    </Button>
                  </div>
                ))}
                <Button
                  className="mb-4"
                  onClick={() => add({ subject: '', username: account.username })}
                >
                  {t('authMethods.addBinding')}
                </Button>
              </>
            )}
          </Form.List>
        </div>
        <Space direction="vertical" className="w-full">
          <Alert type="warning" showIcon message={t('authMethods.sessionsHelp')} />
          <Button type="primary" htmlType="submit" loading={saving}>
            {t('authMethods.save')}
          </Button>
        </Space>
      </Form>
    </div>
  );
};
