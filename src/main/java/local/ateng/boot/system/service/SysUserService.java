package local.ateng.boot.system.service;

import com.mybatisflex.core.paginate.Page;
import com.mybatisflex.core.service.IService;
import local.ateng.boot.system.bo.SysUserLoginBo;
import local.ateng.boot.system.bo.SysUserPageBo;
import local.ateng.boot.system.entity.SysUser;
import local.ateng.boot.system.vo.SysUserVo;

import java.util.List;

/**
 * 存储用户的基本信息 服务层。
 *
 * @author 孔余
 * @since 1.0.0
 */
public interface SysUserService extends IService<SysUser> {

    // 登录
    SysUserVo loginUser(SysUserLoginBo bo);

    // 新增用户
    void addUser(SysUser entity);

    // 分页查询
    Page<SysUser> pageUser(SysUserPageBo bo);

    // 批量删除用户
    void deleteBatchUser(List<Long> ids);

    // 修改用户
    void updateUser(SysUser entity);

    // 根据用户id查询角色列表
    List<String> getUserRoleName(Integer id);

    // 根据用户id查询权限列表
    List<String> getUserPermissionName(Integer id);

    // 任务重试测试
    void userRetry();
}
