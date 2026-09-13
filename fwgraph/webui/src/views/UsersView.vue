<template>
  <div>
    <header class="ins-head">
      <div class="ins-head-row">
        <h1 class="ins-title"><span class="ins-ico"><component :is="NAV_ICONS.User" :size="18" /></span>用户管理</h1>
        <div class="ins-actions">
          <el-button :icon="RefreshCw" :loading="loading" @click="loadUsers">刷新</el-button>
          <el-button type="primary" @click="openCreate">新建用户</el-button>
        </div>
      </div>
      <p class="ins-sub">平台账号与角色权限管理。</p>
    </header>

    <el-card shadow="never" class="block">
      <el-table :data="users" size="small" v-loading="loading">
        <el-table-column prop="username" label="用户名" min-width="140" />
        <el-table-column label="角色" width="110">
          <template #default="{ row }">
            <el-tag size="small" :type="row.role === 'admin' ? 'warning' : 'info'" effect="dark">
              {{ row.role === 'admin' ? '管理员' : '普通用户' }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column label="状态" width="100">
          <template #default="{ row }">
            <el-tag size="small" :type="row.disabled ? 'danger' : 'success'" effect="plain">
              {{ row.disabled ? '已禁用' : '正常' }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column label="创建时间" width="180">
          <template #default="{ row }">{{ fmtTime(row.created_at) }}</template>
        </el-table-column>
        <el-table-column label="操作" width="150">
          <template #default="{ row }">
            <el-button size="small" text type="primary" @click="openEdit(row)">编辑</el-button>
            <el-button size="small" text type="danger" @click="removeUser(row)">删除</el-button>
          </template>
        </el-table-column>
      </el-table>
    </el-card>

    <!-- 新建用户 -->
    <el-dialog v-model="createVisible" title="新建用户" width="420px">
      <el-form label-width="90px">
        <el-form-item label="用户名">
          <el-input v-model="createForm.username" placeholder="登录用户名" />
        </el-form-item>
        <el-form-item label="密码">
          <el-input v-model="createForm.password" type="password" show-password />
        </el-form-item>
        <el-form-item label="角色">
          <el-select v-model="createForm.role" style="width: 100%">
            <el-option label="普通用户" value="user" />
            <el-option label="管理员" value="admin" />
          </el-select>
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="createVisible = false">取消</el-button>
        <el-button type="primary" :loading="saving" @click="createUser">创建</el-button>
      </template>
    </el-dialog>

    <!-- 编辑用户 -->
    <el-dialog v-model="editVisible" :title="`编辑用户 ${editForm.username}`" width="420px">
      <el-form label-width="90px">
        <el-form-item label="角色">
          <el-select v-model="editForm.role" style="width: 100%">
            <el-option label="普通用户" value="user" />
            <el-option label="管理员" value="admin" />
          </el-select>
        </el-form-item>
        <el-form-item label="账号状态">
          <el-switch
            v-model="editForm.disabled"
            active-text="禁用"
            inactive-text="正常"
            inline-prompt
          />
        </el-form-item>
        <el-form-item label="重置密码">
          <el-input
            v-model="editForm.password"
            type="password"
            show-password
            placeholder="留空则不修改密码"
          />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="editVisible = false">取消</el-button>
        <el-button type="primary" :loading="saving" @click="saveEdit">保存</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { NAV_ICONS } from '../workbench/icons.js'
import { onMounted, ref } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { api } from '../api'

const users = ref([])
const loading = ref(false)
const saving = ref(false)
const createVisible = ref(false)
const editVisible = ref(false)
const createForm = ref({ username: '', password: '', role: 'user' })
const editForm = ref({ username: '', role: 'user', disabled: false, password: '' })

function fmtTime (iso) {
  if (!iso) return ''
  const d = new Date(iso)
  return isNaN(d) ? iso : d.toLocaleString()
}

async function loadUsers () {
  loading.value = true
  try {
    users.value = await api('/users')
  } catch (e) {
    ElMessage.error('用户列表加载失败: ' + e.message)
  } finally {
    loading.value = false
  }
}

function openCreate () {
  createForm.value = { username: '', password: '', role: 'user' }
  createVisible.value = true
}

async function createUser () {
  if (!createForm.value.username || !createForm.value.password) {
    ElMessage.warning('请填写用户名和密码')
    return
  }
  saving.value = true
  try {
    await api('/users', { method: 'POST', body: {
      username: createForm.value.username.trim(),
      password: createForm.value.password,
      role: createForm.value.role
    } })
    ElMessage.success('用户已创建')
    createVisible.value = false
    await loadUsers()
  } catch (e) {
    ElMessage.error('创建失败: ' + e.message)
  } finally {
    saving.value = false
  }
}

function openEdit (row) {
  editForm.value = {
    username: row.username,
    role: row.role,
    disabled: !!row.disabled,
    password: ''
  }
  editVisible.value = true
}

async function saveEdit () {
  saving.value = true
  const body = { role: editForm.value.role, disabled: editForm.value.disabled }
  if (editForm.value.password) body.password = editForm.value.password
  try {
    await api(`/users/${encodeURIComponent(editForm.value.username)}`, { method: 'PATCH', body })
    ElMessage.success('已保存')
    editVisible.value = false
    await loadUsers()
  } catch (e) {
    ElMessage.error('保存失败: ' + e.message)
  } finally {
    saving.value = false
  }
}

async function removeUser (row) {
  try {
    await ElMessageBox.confirm(
      `确定删除用户「${row.username}」吗？该操作不可恢复。`,
      '删除用户',
      { type: 'warning', confirmButtonText: '删除', cancelButtonText: '取消' }
    )
  } catch { return }
  try {
    await api(`/users/${encodeURIComponent(row.username)}`, { method: 'DELETE' })
    ElMessage.success('已删除')
    await loadUsers()
  } catch (e) {
    ElMessage.error('删除失败: ' + e.message)
  }
}

onMounted(loadUsers)
</script>

<style scoped>
.block { margin-bottom: 14px; }
.row-between { display: flex; justify-content: space-between; align-items: center; }
</style>
