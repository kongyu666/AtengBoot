package local.ateng.boot.system.vo;

import com.mybatisflex.annotation.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.Serial;
import java.io.Serializable;
import java.sql.Timestamp;
import java.util.List;

/**
 * 存储用户的基本信息 实体类。
 *
 * @author 孔余
 * @since 1.0.0
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Table("sys_user")
public class SysUserVo implements Serializable {

    @Serial
    private static final long serialVersionUID = 1L;

    private Integer userId;
    private String userName;
    private String password;
    private String nickName;
    private String sex;
    private String email;
    private String phoneNumber;
    private Timestamp createTime;
    private Timestamp updateTime;
    /**
     * token
     */
    private String satoken;
    /**
     * 菜单权限
     */
    private List<String> permissionList;

    /**
     * 角色权限
     */
    private List<String> roleList;

}
